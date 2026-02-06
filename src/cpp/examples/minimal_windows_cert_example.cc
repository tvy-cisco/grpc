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

// Minimal example showing Windows Certificate Store integration with gRPC mTLS

#ifdef _WIN32

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/tls_credentials_options.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <windows.h>

#include <fstream>
#include <iostream>
#include <sstream>

#include "src/cpp/common/tls_custom_signing_callback.h"


// Simple helper to load file as string
std::string LoadFile(const std::string& filename) {
  std::ifstream file(filename);
  std::stringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

// Convert certificate to PEM format
std::string CertToPEM(PCCERT_CONTEXT cert) {
  DWORD pem_size = 0;
  CryptBinaryToStringA(cert->pbCertEncoded, cert->cbCertEncoded,
                       CRYPT_STRING_BASE64HEADER, nullptr, &pem_size);

  std::string pem(pem_size, '\0');
  CryptBinaryToStringA(cert->pbCertEncoded, cert->cbCertEncoded,
                       CRYPT_STRING_BASE64HEADER, &pem[0], &pem_size);
  pem.resize(pem_size - 1);  // Remove null terminator
  return pem;
}

// Minimal signing callback using Windows NCRYPT
grpc::experimental::TlsSigningResult SignWithNCrypt(
    PCCERT_CONTEXT cert, grpc::experimental::TlsSignatureAlgorithm algorithm,
    const uint8_t* input, size_t input_len) {
  NCRYPT_KEY_HANDLE key = 0;
  DWORD key_spec = 0;
  BOOL must_free = FALSE;

  // Get the private key handle
  if (!CryptAcquireCertificatePrivateKey(
          cert, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, nullptr, &key, &key_spec,
          &must_free)) {
    return grpc::experimental::TlsSigningResult::Error(
        "Cannot access private key");
  }

  // Simple RSA-SHA256 example (extend for other algorithms)
  BCRYPT_PKCS1_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM};

  // Get signature size
  DWORD sig_size = 0;
  NCryptSignHash(key, &padding, (BYTE*)input, (DWORD)input_len, nullptr, 0,
                 &sig_size, BCRYPT_PAD_PKCS1);

  // Sign the data
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
              << " <cert_subject> <ca_cert.pem> <server:port>\n";
    std::cerr << "Example: " << argv[0]
              << " \"CN=MyClient\" ca-cert.pem localhost:50051\n";
    return 1;
  }

  std::string cert_subject = argv[1];
  std::string ca_pem_file = argv[2];
  std::string server_address = argv[3];

  // Step 1: Find certificate in Windows Certificate Store
  HCERTSTORE store = CertOpenSystemStoreA(0, "MY");
  if (!store) {
    std::cerr << "Failed to open certificate store\n";
    return 1;
  }

  PCCERT_CONTEXT cert = CertFindCertificateInStore(
      store, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_A,
      cert_subject.c_str(), nullptr);

  CertCloseStore(store, 0);

  if (!cert) {
    std::cerr << "Certificate not found: " << cert_subject << "\n";
    return 1;
  }

  std::cout << "Found certificate: " << cert_subject << "\n";

  // Step 2: Convert certificate to PEM
  std::string cert_pem = CertToPEM(cert);

  // Step 3: Create signing callback
  auto signing_callback = [cert](grpc::experimental::TlsSignatureAlgorithm algo,
                                 const uint8_t* data, size_t len) {
    return SignWithNCrypt(cert, algo, data, len);
  };

  // Step 4: Load CA certificates
  std::string ca_pem = LoadFile(ca_pem_file);
  if (ca_pem.empty()) {
    std::cerr << "Failed to load CA certificate: " << ca_pem_file << "\n";
    CertFreeCertificateContext(cert);
    return 1;
  }

  // Step 5: Create TLS credentials with custom signing
  grpc::experimental::TlsChannelCredentialsOptions tls_opts;

  // Set root CA and client certificate
  grpc::experimental::IdentityKeyCertPair identity;
  identity.certificate_chain = cert_pem;
  // private_key is empty - using signing callback instead

  auto provider =
      std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
          ca_pem,
          std::vector<grpc::experimental::IdentityKeyCertPair>{identity});
  tls_opts.set_root_certificate_provider(provider);
  tls_opts.set_identity_certificate_provider(provider);
  tls_opts.watch_root_certs();
  tls_opts.watch_identity_key_cert_pairs();

  // Set custom signing callback
  tls_opts.set_custom_signing_callback(signing_callback);
  tls_opts.set_verify_server_certs(true);

  auto creds = grpc::experimental::TlsCredentials(tls_opts);

  // Step 6: Create channel
  auto channel = grpc::CreateChannel(server_address, creds);

  std::cout << "Created secure channel to " << server_address << "\n";
  std::cout << "Using certificate from Windows Certificate Store\n";
  std::cout << "Private key signing via NCRYPT\n";

  // Your gRPC calls would go here
  // auto stub = YourService::NewStub(channel);
  // ...

  // Cleanup
  CertFreeCertificateContext(cert);

  std::cout << "Success!\n";
  return 0;
}

#else

#include <iostream>

int main() {
  std::cerr << "This example requires Windows\n";
  return 1;
}

#endif  // _WIN32
