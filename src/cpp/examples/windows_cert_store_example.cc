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

// Example implementation showing how to use Windows Certificate Store
// with NCRYPT for mTLS in gRPC C++

#ifdef _WIN32

#include <bcrypt.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/tls_credentials_options.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <windows.h>

#include <memory>
#include <string>
#include <vector>

#include "src/cpp/common/tls_custom_signing_callback.h"


#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

namespace grpc {
namespace examples {

// Helper class to manage Windows Certificate Context
class WindowsCertificateHandle {
 public:
  explicit WindowsCertificateHandle(PCCERT_CONTEXT cert_context)
      : cert_context_(cert_context) {}

  ~WindowsCertificateHandle() {
    if (cert_context_) {
      CertFreeCertificateContext(cert_context_);
    }
  }

  PCCERT_CONTEXT get() const { return cert_context_; }

  // Delete copy operations
  WindowsCertificateHandle(const WindowsCertificateHandle&) = delete;
  WindowsCertificateHandle& operator=(const WindowsCertificateHandle&) = delete;

 private:
  PCCERT_CONTEXT cert_context_;
};

// Convert Windows Certificate to PEM format
std::string CertificateToPEM(PCCERT_CONTEXT cert_context) {
  DWORD pem_size = 0;

  // Get required buffer size
  if (!CryptBinaryToStringA(cert_context->pbCertEncoded,
                            cert_context->cbCertEncoded,
                            CRYPT_STRING_BASE64HEADER, nullptr, &pem_size)) {
    return "";
  }

  std::vector<char> pem_buffer(pem_size);

  // Convert to PEM
  if (!CryptBinaryToStringA(
          cert_context->pbCertEncoded, cert_context->cbCertEncoded,
          CRYPT_STRING_BASE64HEADER, pem_buffer.data(), &pem_size)) {
    return "";
  }

  return std::string(pem_buffer.data(),
                     pem_size - 1);  // Exclude null terminator
}

// Map TLS signature algorithm to Windows BCrypt algorithm and padding
struct WindowsSigningParams {
  LPCWSTR hash_algorithm;
  DWORD padding_flags;
  BCRYPT_PKCS1_PADDING_INFO pkcs1_padding;
  BCRYPT_PSS_PADDING_INFO pss_padding;
  bool use_pss;
};

WindowsSigningParams GetSigningParams(
    grpc::experimental::TlsSignatureAlgorithm algorithm) {
  WindowsSigningParams params = {};
  params.use_pss = false;

  switch (algorithm) {
    case grpc::experimental::TlsSignatureAlgorithm::kRsaPkcs1Sha256:
      params.hash_algorithm = BCRYPT_SHA256_ALGORITHM;
      params.padding_flags = BCRYPT_PAD_PKCS1;
      params.pkcs1_padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
      break;

    case grpc::experimental::TlsSignatureAlgorithm::kRsaPkcs1Sha384:
      params.hash_algorithm = BCRYPT_SHA384_ALGORITHM;
      params.padding_flags = BCRYPT_PAD_PKCS1;
      params.pkcs1_padding.pszAlgId = BCRYPT_SHA384_ALGORITHM;
      break;

    case grpc::experimental::TlsSignatureAlgorithm::kRsaPkcs1Sha512:
      params.hash_algorithm = BCRYPT_SHA512_ALGORITHM;
      params.padding_flags = BCRYPT_PAD_PKCS1;
      params.pkcs1_padding.pszAlgId = BCRYPT_SHA512_ALGORITHM;
      break;

    case grpc::experimental::TlsSignatureAlgorithm::kRsaPssSha256:
      params.hash_algorithm = BCRYPT_SHA256_ALGORITHM;
      params.padding_flags = BCRYPT_PAD_PSS;
      params.use_pss = true;
      params.pss_padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
      params.pss_padding.cbSalt = 32;  // SHA256 hash size
      break;

    case grpc::experimental::TlsSignatureAlgorithm::kRsaPssSha384:
      params.hash_algorithm = BCRYPT_SHA384_ALGORITHM;
      params.padding_flags = BCRYPT_PAD_PSS;
      params.use_pss = true;
      params.pss_padding.pszAlgId = BCRYPT_SHA384_ALGORITHM;
      params.pss_padding.cbSalt = 48;  // SHA384 hash size
      break;

    case grpc::experimental::TlsSignatureAlgorithm::kRsaPssSha512:
      params.hash_algorithm = BCRYPT_SHA512_ALGORITHM;
      params.padding_flags = BCRYPT_PAD_PSS;
      params.use_pss = true;
      params.pss_padding.pszAlgId = BCRYPT_SHA512_ALGORITHM;
      params.pss_padding.cbSalt = 64;  // SHA512 hash size
      break;

    case grpc::experimental::TlsSignatureAlgorithm::kEcdsaSecp256r1Sha256:
    case grpc::experimental::TlsSignatureAlgorithm::kEcdsaSecp384r1Sha384:
    case grpc::experimental::TlsSignatureAlgorithm::kEcdsaSecp521r1Sha512:
      // ECDSA doesn't use padding in the same way
      params.padding_flags = 0;
      break;
  }

  return params;
}

// Windows NCRYPT signing callback
grpc::experimental::TlsSigningResult WindowsNCryptSigningCallback(
    PCCERT_CONTEXT cert_context,
    grpc::experimental::TlsSignatureAlgorithm algorithm, const uint8_t* input,
    size_t input_len) {
  NCRYPT_KEY_HANDLE key_handle = 0;
  DWORD key_spec = 0;
  BOOL must_free = FALSE;

  // Acquire the private key handle using NCRYPT
  if (!CryptAcquireCertificatePrivateKey(
          cert_context,
          CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_CACHE_FLAG,
          nullptr, &key_handle, &key_spec, &must_free)) {
    DWORD error = GetLastError();
    return grpc::experimental::TlsSigningResult::Error(
        "Failed to acquire private key. Error: " + std::to_string(error));
  }

  // Get signing parameters for the algorithm
  WindowsSigningParams params = GetSigningParams(algorithm);

  // Determine padding info pointer
  void* padding_info = nullptr;
  if (params.padding_flags == BCRYPT_PAD_PKCS1) {
    padding_info = &params.pkcs1_padding;
  } else if (params.padding_flags == BCRYPT_PAD_PSS) {
    padding_info = &params.pss_padding;
  }

  // Get signature size
  DWORD signature_size = 0;
  SECURITY_STATUS status =
      NCryptSignHash(key_handle, padding_info, const_cast<BYTE*>(input),
                     static_cast<DWORD>(input_len), nullptr, 0, &signature_size,
                     params.padding_flags);

  if (status != ERROR_SUCCESS) {
    if (must_free) NCryptFreeObject(key_handle);
    return grpc::experimental::TlsSigningResult::Error(
        "Failed to get signature size. Status: " + std::to_string(status));
  }

  // Allocate buffer and sign
  std::vector<uint8_t> signature(signature_size);
  status =
      NCryptSignHash(key_handle, padding_info, const_cast<BYTE*>(input),
                     static_cast<DWORD>(input_len), signature.data(),
                     signature_size, &signature_size, params.padding_flags);

  // Free the key handle if necessary
  if (must_free) {
    NCryptFreeObject(key_handle);
  }

  if (status != ERROR_SUCCESS) {
    return grpc::experimental::TlsSigningResult::Error(
        "Failed to sign hash. Status: " + std::to_string(status));
  }

  // Resize to actual signature size
  signature.resize(signature_size);

  return grpc::experimental::TlsSigningResult::Success(signature);
}

// Find certificate in Windows Certificate Store by subject name
std::unique_ptr<WindowsCertificateHandle> FindCertificateBySubject(
    const std::string& store_name, const std::string& subject_name) {
  // Open the certificate store
  HCERTSTORE cert_store = CertOpenSystemStoreA(0, store_name.c_str());
  if (!cert_store) {
    return nullptr;
  }

  // Find certificate by subject string
  PCCERT_CONTEXT cert_context = CertFindCertificateInStore(
      cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
      CERT_FIND_SUBJECT_STR_A, subject_name.c_str(), nullptr);

  CertCloseStore(cert_store, 0);

  if (!cert_context) {
    return nullptr;
  }

  return std::make_unique<WindowsCertificateHandle>(cert_context);
}

// Example: Create TLS credentials using Windows Certificate Store
std::shared_ptr<grpc::ChannelCredentials> CreateWindowsCertStoreCredentials(
    const std::string& cert_subject_name, const std::string& root_cert_pem) {
  // Find the certificate in the Windows Certificate Store
  auto cert_handle = FindCertificateBySubject("MY", cert_subject_name);
  if (!cert_handle) {
    std::cerr << "Failed to find certificate: " << cert_subject_name
              << std::endl;
    return nullptr;
  }

  // Convert certificate to PEM format
  std::string cert_pem = CertificateToPEM(cert_handle->get());
  if (cert_pem.empty()) {
    std::cerr << "Failed to convert certificate to PEM" << std::endl;
    return nullptr;
  }

  // Create custom signing callback
  // Note: We need to keep cert_handle alive, so we capture it in the callback
  PCCERT_CONTEXT cert_context = cert_handle->get();

  auto signing_callback =
      [cert_context](grpc::experimental::TlsSignatureAlgorithm algorithm,
                     const uint8_t* input,
                     size_t input_len) -> grpc::experimental::TlsSigningResult {
    return WindowsNCryptSigningCallback(cert_context, algorithm, input,
                                        input_len);
  };

  // Create TLS credentials options
  grpc::experimental::TlsChannelCredentialsOptions tls_options;

  // Set root certificates (CA bundle) and client certificate
  grpc::experimental::IdentityKeyCertPair identity;
  identity.certificate_chain = cert_pem;
  // private_key is empty - we use the signing callback instead

  std::vector<grpc::experimental::IdentityKeyCertPair> identities;
  if (!cert_pem.empty()) {
    identities.push_back(identity);
  }

  auto provider =
      std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
          root_cert_pem, identities);

  tls_options.set_root_certificate_provider(provider);
  tls_options.set_identity_certificate_provider(provider);
  tls_options.watch_root_certs();
  tls_options.watch_identity_key_cert_pairs();

  // Set custom signing callback
  tls_options.set_custom_signing_callback(signing_callback);

  // Enable server certificate verification
  tls_options.set_verify_server_certs(true);

  // Create and return credentials
  return grpc::experimental::TlsCredentials(tls_options);
}

// Example: Create a gRPC channel with Windows Certificate Store mTLS
std::shared_ptr<grpc::Channel> CreateSecureChannel(
    const std::string& server_address, const std::string& cert_subject_name,
    const std::string& root_cert_pem) {
  auto credentials =
      CreateWindowsCertStoreCredentials(cert_subject_name, root_cert_pem);

  if (!credentials) {
    return nullptr;
  }

  return grpc::CreateChannel(server_address, credentials);
}

}  // namespace examples
}  // namespace grpc

// Example usage:
//
// int main() {
//   // Load root CA certificates (PEM format)
//   std::string root_cert_pem = LoadFileAsString("ca-cert.pem");
//
//   // Create channel using certificate from Windows Cert Store
//   auto channel = grpc::examples::CreateSecureChannel(
//       "localhost:50051",
//       "CN=MyClientCert",  // Subject name of cert in Windows Cert Store
//       root_cert_pem);
//
//   if (!channel) {
//     std::cerr << "Failed to create secure channel" << std::endl;
//     return 1;
//   }
//
//   // Use the channel with your gRPC stub
//   auto stub = MyService::NewStub(channel);
//   // ... make gRPC calls ...
//
//   return 0;
// }

#endif  // _WIN32
