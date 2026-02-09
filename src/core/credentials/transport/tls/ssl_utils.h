//
//
// Copyright 2015 gRPC authors.
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
//

#ifndef GRPC_SRC_CORE_CREDENTIALS_TRANSPORT_TLS_SSL_UTILS_H
#define GRPC_SRC_CORE_CREDENTIALS_TRANSPORT_TLS_SSL_UTILS_H

#include <grpc/grpc_crl_provider.h>
#include <grpc/grpc_security.h>
#include <grpc/grpc_security_constants.h>
#include <grpc/slice.h>
#include <grpc/support/port_platform.h>
#include <stddef.h>

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "src/core/credentials/transport/security_connector.h"
#include "src/core/lib/iomgr/error.h"
#include "src/core/tsi/ssl/key_logging/ssl_key_logging.h"
#include "src/core/tsi/ssl_transport_security.h"
#include "src/core/tsi/transport_security_interface.h"
#include "src/core/util/ref_counted_ptr.h"

// --- Util ---

// Check ALPN information returned from SSL handshakes.
grpc_error_handle grpc_ssl_check_alpn(const tsi_peer* peer);

// Check peer name information returned from SSL handshakes.
grpc_error_handle grpc_ssl_check_peer_name(absl::string_view peer_name, const tsi_peer* peer);
// Compare target_name information extracted from SSL security connectors.
int grpc_ssl_cmp_target_name(absl::string_view target_name, absl::string_view other_target_name,
                             absl::string_view overridden_target_name,
                             absl::string_view other_overridden_target_name);

namespace grpc_core {
// Check the host that will be set for a call is acceptable.
absl::Status SslCheckCallHost(absl::string_view host, absl::string_view target_name,
                              absl::string_view overridden_target_name,
                              grpc_auth_context* auth_context);
}  // namespace grpc_core

// Return HTTP2-compliant cipher suites that gRPC accepts by default.
const char* grpc_get_ssl_cipher_suites(void);

// Map from grpc_ssl_client_certificate_request_type to
// tsi_client_certificate_request_type.
tsi_client_certificate_request_type grpc_get_tsi_client_certificate_request_type(
    grpc_ssl_client_certificate_request_type grpc_request_type);

// Map grpc_tls_version to tsi_tls_version.
tsi_tls_version grpc_get_tsi_tls_version(grpc_tls_version tls_version);

// Return an array of strings containing alpn protocols.
const char** grpc_fill_alpn_protocol_strings(size_t* num_alpn_protocols);

// Initialize TSI SSL server/client handshaker factory.
grpc_security_status grpc_ssl_tsi_client_handshaker_factory_init(
    tsi_ssl_pem_key_cert_pair* key_cert_pair, const char* pem_root_certs,
    bool skip_server_certificate_verification, tsi_tls_version min_tls_version,
    tsi_tls_version max_tls_version, tsi_ssl_session_cache* ssl_session_cache,
    tsi::TlsSessionKeyLoggerCache::TlsSessionKeyLogger* tls_session_key_logger,
    const char* crl_directory, std::shared_ptr<grpc_core::experimental::CrlProvider> crl_provider,
    tsi_ssl_client_handshaker_factory** handshaker_factory);

grpc_security_status grpc_ssl_tsi_server_handshaker_factory_init(
    tsi_ssl_pem_key_cert_pair* key_cert_pairs, size_t num_key_cert_pairs,
    const char* pem_root_certs, grpc_ssl_client_certificate_request_type client_certificate_request,
    tsi_tls_version min_tls_version, tsi_tls_version max_tls_version,
    tsi::TlsSessionKeyLoggerCache::TlsSessionKeyLogger* tls_session_key_logger,
    const char* crl_directory, bool send_client_ca_list,
    std::shared_ptr<grpc_core::experimental::CrlProvider> crl_provider,
    tsi_ssl_server_handshaker_factory** handshaker_factory);

// Free the memory occupied by key cert pairs.
void grpc_tsi_ssl_pem_key_cert_pairs_destroy(tsi_ssl_pem_key_cert_pair* kp,
                                             size_t num_key_cert_pairs);
// Exposed for testing only.
grpc_core::RefCountedPtr<grpc_auth_context> grpc_ssl_peer_to_auth_context(
    const tsi_peer* peer, const char* transport_security_type);
tsi_peer grpc_shallow_peer_from_ssl_auth_context(const grpc_auth_context* auth_context);
void grpc_shallow_peer_destruct(tsi_peer* peer);
int grpc_ssl_host_matches_name(const tsi_peer* peer, absl::string_view peer_name);

// --- Default SSL Root Store. ---
namespace grpc_core {

// The class implements default SSL root store.
class DefaultSslRootStore {
 public:
  // Gets the default SSL root store. Returns nullptr if not found.
  static const tsi_ssl_root_certs_store* GetRootStore();

  // Gets the default PEM root certificate.
  static const char* GetPemRootCerts();

 protected:
  // Returns default PEM root certificates in nullptr terminated grpc_slice.
  // This function is protected instead of private, so that it can be tested.
  static grpc_slice ComputePemRootCerts();

 private:
  // Construct me not!
  DefaultSslRootStore();

  // Initialization of default SSL root store.
  static void InitRootStore();

  // One-time initialization of default SSL root store.
  static void InitRootStoreOnce();

  // SSL root store in tsi_ssl_root_certs_store object.
  static tsi_ssl_root_certs_store* default_root_store_;

  // Default PEM root certificates.
  static grpc_slice default_pem_root_certs_;
};

// Enum class representing TLS signature algorithm identifiers from BoringSSL.
// The values correspond to the SSL_SIGN_* macros in <openssl/ssl.h>.
enum class SignatureAlgorithm : uint16_t {
  kRsaPkcs1Sha256 = 0x0401,        // SSL_SIGN_RSA_PKCS1_SHA256
  kRsaPkcs1Sha384 = 0x0501,        // SSL_SIGN_RSA_PKCS1_SHA384
  kRsaPkcs1Sha512 = 0x0601,        // SSL_SIGN_RSA_PKCS1_SHA512
  kEcdsaSecp256r1Sha256 = 0x0403,  // SSL_SIGN_ECDSA_SECP256R1_SHA256
  kEcdsaSecp384r1Sha384 = 0x0503,  // SSL_SIGN_ECDSA_SECP384R1_SHA384
  kEcdsaSecp521r1Sha512 = 0x0603,  // SSL_SIGN_ECDSA_SECP521R1_SHA512
  kRsaPssRsaeSha256 = 0x0804,      // SSL_SIGN_RSA_PSS_RSAE_SHA256
  kRsaPssRsaeSha384 = 0x0805,      // SSL_SIGN_RSA_PSS_RSAE_SHA384
  kRsaPssRsaeSha512 = 0x0806,      // SSL_SIGN_RSA_PSS_RSAE_SHA512
};

// Callback type for the done_callback parameter in CustomPrivateKeySign.
// Users must invoke this callback with the signed bytes when complete.
using PrivateKeySignDoneCallback = std::function<void(absl::StatusOr<std::string> signed_data)>;

// A user's implementation MUST invoke done_callback with the signed bytes.
// This will let gRPC take control when the async operation is complete.
// MUST not block
// MUST support concurrent calls
using CustomPrivateKeySign =
    std::function<void(absl::string_view data_to_sign, SignatureAlgorithm signature_algorithm,
                       PrivateKeySignDoneCallback done_callback)>;

// PrivateKey variant that can hold either a PEM-encoded private key string
// or a custom private key signing function.
using PrivateKey = std::variant<std::string, CustomPrivateKeySign>;

class PemKeyCertPair {
 public:
  // Constructor accepting a string private key
  PemKeyCertPair(absl::string_view private_key, absl::string_view cert_chain)
      : private_key_(std::string(private_key)), cert_chain_(cert_chain) {}

  // Constructor accepting a custom private key signing function
  PemKeyCertPair(CustomPrivateKeySign private_key_sign, absl::string_view cert_chain)
      : private_key_(std::move(private_key_sign)), cert_chain_(cert_chain) {}

  // Movable.
  PemKeyCertPair(PemKeyCertPair&& other) noexcept {
    private_key_ = std::move(other.private_key_);
    cert_chain_ = std::move(other.cert_chain_);
  }
  PemKeyCertPair& operator=(PemKeyCertPair&& other) noexcept {
    private_key_ = std::move(other.private_key_);
    cert_chain_ = std::move(other.cert_chain_);
    return *this;
  }

  // Copyable - CustomPrivateKeySign is wrapped in shared_ptr
  PemKeyCertPair(const PemKeyCertPair& other) = default;
  PemKeyCertPair& operator=(const PemKeyCertPair& other) = default;

  bool operator==(const PemKeyCertPair& other) const {
    // For custom signing functions, we cannot compare them meaningfully
    if (private_key_.index() != other.private_key_.index()) {
      return false;
    }
    if (std::holds_alternative<std::string>(private_key_)) {
      return std::get<std::string>(private_key_) == std::get<std::string>(other.private_key_) &&
             this->cert_chain() == other.cert_chain();
    }
    // For custom signing functions, assume they're not equal unless same object
    return false;
  }

  const PrivateKey& private_key() const { return private_key_; }
  const std::string& cert_chain() const { return cert_chain_; }

  // Helper to check if using custom signing
  bool has_custom_signing() const {
    return std::holds_alternative<CustomPrivateKeySign>(private_key_);
  }

  // Helper to get the string private key (returns empty if custom signing)
  std::string private_key_string() const {
    if (std::holds_alternative<std::string>(private_key_)) {
      return std::get<std::string>(private_key_);
    }
    return "";
  }

 private:
  PrivateKey private_key_;
  std::string cert_chain_;
};

using PemKeyCertPairList = std::vector<PemKeyCertPair>;

}  // namespace grpc_core

#endif  // GRPC_SRC_CORE_CREDENTIALS_TRANSPORT_TLS_SSL_UTILS_H
