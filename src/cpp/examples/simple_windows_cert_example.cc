//
// Copyright 2026 gRPC authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Simple example showing Windows Certificate Store integration

#ifdef _WIN32

#include <bcrypt.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/tls_credentials_options.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <windows.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include "src/cpp/common/tls_custom_signing_callback.h"


std::string LoadFile(const std::string& path) {
  std::ifstream file(path);
  std::stringstream buf;
  buf << file.rdbuf();
  return buf.str();
}

// Convert certificate to PEM
std::string CertToPEM(PCCERT_CONTEXT cert) {
  DWORD pem_size = 0;
  CryptBinaryToStringA(cert->pbCertEncoded, cert->cbCertEncoded,
                       CRYPT_STRING_BASE64HEADER, nullptr, &pem_size);

  std::string pem(pem_size, '\0');
  CryptBinaryToStringA(cert->pbCertEncoded, cert->cbCertEncoded,
                       CRYPT_STRING_BASE64HEADER, &pem[0], &pem_size);
  pem.resize(pem_size - 1);
  retFind certificate in Windows Certificate Store HCERTSTORE store =
      CertOpenSystemStoreA(0, "MY");
  if (!store) {
    std::cerr << "Failed to open certificate store\n";
    return 1;
  }

  PCCERT_CONTEXT cert = CertFindCertificateInStore(
      store, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_A, argv[1], nullptr);

  CertCloseStore(store, 0);

  if (!cert) {
    std::cerr << "Certificate not found: " << argv[1] << "\n";
    return 1;
  }

  // Convert certificate to PEM
  std::string cert_pem = CertToPEM(cert);

  // Create signing callback
  auto signing_callback = [cert](grpc::experimental::TlsSignatureAlgorithm algo,
                                 const uint8_t* data, size_t len) {
    return SignWithNCrypt(cert, algo, data, len);
  }; const uint8_t* input,
    size_t input_len) {
    NCRYPT_KEY_HANDLE key = 0;
    DWORD key_spec = 0;
    BOOL must_free = FALSE;

    if (!CryptAcquireCertificatePrivateKey(
            cert, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, nullptr, &key, &key_spec,
            &must_free)) {
      return grpc::experimental::TlsSigningResult::Error(
          "Cannot access private key");
    }

    BCRYPT_PKCS1_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM};

    DWORD sig_size = 0;
    NCryptSignHash(key, &padding, (BYTE*)input, (DWORD)input_len, nullptr, 0,
                   &sig_size, BCRYPT_PAD_PKCS1);

    std::vector<uint8_t> signature(sig_size);
    SECURITY_STATUS status =
        NCryptSignHash(key, &padding, (BYTE*)input, (DWORD)input_len,
                       signature.data(), sig_size, &sig_size, BCRYPT_PAD_PKCS1);

    if (must_free) NCryptFreeObject(key);

    if (status != ERROR_SUCCESS) {
      return grpc::experimental::TlsSigningResult::Error("Signing failed");
    }

    signature.resize(sig_size);
    return grpc::experimental::TlsSigningResult::Success(signature);
  }

  int main(int argc, char** argv) {
    if (argc < 4) {
      std::cerr << "Usage: " << argv[0]
                << " <cert_subject> <ca.pem> <server:port>\n";
      return 1;
    }

    // Load CA certificates
    std::string ca_pem = LoadFile(argv[2]);

    // Find certificate in Windows Certificate Store
    HCERTSTORE store = CertOpenSystemStoreA(0, "MY");
    if (!store) {
      std::cerr << "Failed to open certificate store\n";
      return 1;
    }

    PCCERT_CONTEXT cert = CertFindCertificateInStore(
        store, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_A, argv[1], nullptr);

    CertCloseStore(store, 0);

    if (!cert) {
      std::cerr << "Certificate not found: " << argv[1] << "\n";
      return 1;
    }

    // Convert certificate to PEM
    std::string cert_pem = CertToPEM(cert);

    // Create signing callback
    auto signing_callback =
        [cert](grpc::experimental::TlsSignatureAlgorithm algo,
               const uint8_t* data,
               size_t len) { return SignWithNCrypt(cert, algo, data, len); };

    // Setup TLS credentials
    grpc::experimental::TlsChannelCredentialsOptions opts;

    // Set root CA and client certificate
    grpc::experimental::IdentityKeyCertPair identity;
    identity.certificate_chain = cert_pem;
    // Note: private_key is empty - we'll use the signing callback instead

    auto provider =
        std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
            ca_pem,
            std::vector<grpc::experimental::IdentityKeyCertPair>{identity});
    opts.set_root_certificate_provider(provider);
    opts.set_identity_certificate_provider(provider);
    opts.watch_root_certs();
    opts.watch_identity_key_cert_pairs();

    // Set custom signing callback
    opts.set_custom_signing_callback(signing_callback);
    opts.set_verify_server_certs(true);

    // Create channel
    auto channel =
        grpc::CreateChannel(argv[3], grpc::experimental::TlsCredentials(opts));

    std::cout << "✓ Channel created with Windows Certificate Store mTLS\n";
    std::cout << "✓ Certificate: " << argv[1] << "\n";
    std::cout << "✓ Server: " << argv[3] << "\n";
    std::cout << "✓ Signing via callback (NCRYPT)\n";

    // Use your gRPC stub here
    // Cleanup
    CertFreeCertificateContext(cert);

    // auto stub = YourService::NewStub(channel);

    return 0;
  }

#include <iostream>

  int main() {
    std::cerr << "This example requires Windows\n";
    return 1;
  }

#endif  // _WIN32

#endif
