//
// Copyright 2020 gRPC authors.
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

#ifndef GRPCPP_SECURITY_TLS_CERTIFICATE_PROVIDER_H
#define GRPCPP_SECURITY_TLS_CERTIFICATE_PROVIDER_H

#include <grpc/credentials.h>
#include <grpc/grpc_security.h>
#include <grpc/grpc_security_constants.h>
#include <grpc/status.h>
#include <grpc/support/port_platform.h>
#include <grpcpp/support/config.h>

#include <functional>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace grpc {
namespace experimental {

// Forward declare types from C-Core
namespace tls_types {
// Enum class representing TLS signature algorithm identifiers from BoringSSL.
enum class SignatureAlgorithm : uint16_t {
  kRsaPkcs1Sha256 = 0x0401,
  kRsaPkcs1Sha384 = 0x0501,
  kRsaPkcs1Sha512 = 0x0601,
  kEcdsaSecp256r1Sha256 = 0x0403,
  kEcdsaSecp384r1Sha384 = 0x0503,
  kEcdsaSecp521r1Sha512 = 0x0603,
  kRsaPssRsaeSha256 = 0x0804,
  kRsaPssRsaeSha384 = 0x0805,
  kRsaPssRsaeSha512 = 0x0806,
};

// Callback type for the done_callback parameter in CustomPrivateKeySign.
// Users must invoke this callback with the signed bytes when complete.
using PrivateKeySignDoneCallback = std::function<void(absl::StatusOr<std::string> signed_data)>;

// Callback type for custom private key signing
using CustomPrivateKeySign =
    std::function<void(absl::string_view data_to_sign, SignatureAlgorithm signature_algorithm,
                       PrivateKeySignDoneCallback done_callback)>;

// Private key variant that can hold either a string or a custom signing function
using PrivateKey = std::variant<std::string, CustomPrivateKeySign>;
}  // namespace tls_types

// Re-export for convenience
using SignatureAlgorithm = tls_types::SignatureAlgorithm;
using CustomPrivateKeySign = tls_types::CustomPrivateKeySign;
using PrivateKey = tls_types::PrivateKey;

// Interface for a class that handles the process to fetch credential data.
// Implementations should be a wrapper class of an internal provider
// implementation.
class GRPCXX_DLL CertificateProviderInterface {
 public:
  virtual ~CertificateProviderInterface() = default;
  virtual grpc_tls_certificate_provider* c_provider() = 0;
};

// A struct that stores the credential data presented to the peer in handshake
// to show local identity. The private_key and certificate_chain should always
// match.
struct GRPCXX_DLL IdentityKeyCertPair {
  // Constructor accepting a string private key
  IdentityKeyCertPair(std::string priv_key, std::string cert_chain)
      : private_key(std::move(priv_key)), certificate_chain(std::move(cert_chain)) {}

  // Constructor accepting a custom private key signing function
  IdentityKeyCertPair(CustomPrivateKeySign priv_key_sign, std::string cert_chain)
      : private_key(std::move(priv_key_sign)), certificate_chain(std::move(cert_chain)) {}

  // Default constructor
  IdentityKeyCertPair() = default;

  PrivateKey private_key;
  std::string certificate_chain;

  // Helper to check if using custom signing
  bool has_custom_signing() const {
    return std::holds_alternative<CustomPrivateKeySign>(private_key);
  }

  // Helper to get the string private key (returns empty if custom signing)
  std::string private_key_string() const {
    if (std::holds_alternative<std::string>(private_key)) {
      return std::get<std::string>(private_key);
    }
    return "";
  }
};

// A basic CertificateProviderInterface implementation that will load credential
// data from static string during initialization. This provider will always
// return the same cert data for all cert names, and reloading is not supported.
class GRPCXX_DLL StaticDataCertificateProvider : public CertificateProviderInterface {
 public:
  StaticDataCertificateProvider(const std::string& root_certificate,
                                const std::vector<IdentityKeyCertPair>& identity_key_cert_pairs);

  explicit StaticDataCertificateProvider(const std::string& root_certificate)
      : StaticDataCertificateProvider(root_certificate, {}) {}

  explicit StaticDataCertificateProvider(
      const std::vector<IdentityKeyCertPair>& identity_key_cert_pairs)
      : StaticDataCertificateProvider("", identity_key_cert_pairs) {}

  ~StaticDataCertificateProvider() override;

  grpc_tls_certificate_provider* c_provider() override { return c_provider_; }

  // Returns an OK status if the following conditions hold:
  // - the root certificates consist of one or more valid PEM blocks, and
  // - every identity key-cert pair has a certificate chain that consists of
  //   valid PEM blocks and has a private key is a valid PEM block.
  absl::Status ValidateCredentials() const;

 private:
  grpc_tls_certificate_provider* c_provider_ = nullptr;
};

// A CertificateProviderInterface implementation that will watch the credential
// changes on the file system. This provider will always return the up-to-date
// cert data for all the cert names callers set through |TlsCredentialsOptions|.
// Several things to note:
// 1. This API only supports one key-cert file and hence one set of identity
// key-cert pair, so SNI(Server Name Indication) is not supported.
// 2. The private key and identity certificate should always match. This API
// guarantees atomic read, and it is the callers' responsibility to do atomic
// updates. There are many ways to atomically update the key and certs in the
// file system. To name a few:
//   1)  creating a new directory, renaming the old directory to a new name, and
//   then renaming the new directory to the original name of the old directory.
//   2)  using a symlink for the directory. When need to change, put new
//   credential data in a new directory, and change symlink.
class GRPCXX_DLL FileWatcherCertificateProvider final : public CertificateProviderInterface {
 public:
  // Constructor to get credential updates from root and identity file paths.
  //
  // @param private_key_path is the file path of the private key.
  // @param identity_certificate_path is the file path of the identity
  // certificate chain.
  // @param root_cert_path is the file path to the root certificate bundle.
  // @param refresh_interval_sec is the refreshing interval that we will check
  // the files for updates.
  FileWatcherCertificateProvider(const std::string& private_key_path,
                                 const std::string& identity_certificate_path,
                                 const std::string& root_cert_path,
                                 unsigned int refresh_interval_sec);
  // Constructor to get credential updates from identity file paths only.
  FileWatcherCertificateProvider(const std::string& private_key_path,
                                 const std::string& identity_certificate_path,
                                 unsigned int refresh_interval_sec)
      : FileWatcherCertificateProvider(private_key_path, identity_certificate_path, "",
                                       refresh_interval_sec) {}
  // Constructor to get credential updates from root file path only.
  FileWatcherCertificateProvider(const std::string& root_cert_path,
                                 unsigned int refresh_interval_sec)
      : FileWatcherCertificateProvider("", "", root_cert_path, refresh_interval_sec) {}

  ~FileWatcherCertificateProvider() override;

  grpc_tls_certificate_provider* c_provider() override { return c_provider_; }

  // Returns an OK status if the following conditions hold:
  // - the currently-loaded root certificates, if any, consist of one or more
  //   valid PEM blocks, and
  // - every currently-loaded identity key-cert pair, if any, has a certificate
  //   chain that consists of valid PEM blocks and has a private key is a valid
  //   PEM block.
  absl::Status ValidateCredentials() const;

 private:
  grpc_tls_certificate_provider* c_provider_ = nullptr;
};

// A CertificateProviderInterface implementation that holds in-memory certificate
// data that can be updated in a thread-safe manner. Supports custom private key
// signing functions.
class GRPCXX_DLL InMemoryCertificateProvider final : public CertificateProviderInterface {
 public:
  // Factory method to create an InMemoryCertificateProvider
  // Takes parameters by value to support both copy and move semantics
  static std::shared_ptr<InMemoryCertificateProvider> Create(
      std::string root_certificate, std::vector<IdentityKeyCertPair> identity_key_cert_pairs);

  ~InMemoryCertificateProvider() override;

  grpc_tls_certificate_provider* c_provider() override { return c_provider_; }

  // Thread-safe methods to update credentials
  void UpdateRootCertificates(const std::string& root_certificates);
  // Takes parameter by value to support both copy and move semantics
  void UpdateIdentityKeyCertPairs(std::vector<IdentityKeyCertPair> identity_key_cert_pairs);

  // Returns an OK status if the following conditions hold:
  // - the root certificates consist of one or more valid PEM blocks, and
  // - every identity key-cert pair has a certificate chain that consists of
  //   valid PEM blocks and (if not using custom signing) has a private key
  //   that is a valid PEM block.
  absl::Status ValidateCredentials() const;

 private:
  // Private constructor - use Create() factory method
  // Takes parameters by value to support both copy and move
  InMemoryCertificateProvider(std::string root_certificate,
                              std::vector<IdentityKeyCertPair> identity_key_cert_pairs);

  grpc_tls_certificate_provider* c_provider_ = nullptr;
};

}  // namespace experimental
}  // namespace grpc

#endif  // GRPCPP_SECURITY_TLS_CERTIFICATE_PROVIDER_H
