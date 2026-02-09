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

#include <grpc/credentials.h>
#include <grpc/grpc_security.h>
#include <grpcpp/security/tls_certificate_provider.h>

#include <memory>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/log/check.h"
#include "src/core/credentials/transport/tls/grpc_tls_certificate_provider.h"
#include "src/core/credentials/transport/tls/ssl_utils.h"

namespace grpc {
namespace experimental {

StaticDataCertificateProvider::StaticDataCertificateProvider(
    const std::string& root_certificate,
    const std::vector<IdentityKeyCertPair>& identity_key_cert_pairs) {
  CHECK(!root_certificate.empty() || !identity_key_cert_pairs.empty());
  grpc_tls_identity_pairs* pairs_core = grpc_tls_identity_pairs_create();
  for (const IdentityKeyCertPair& pair : identity_key_cert_pairs) {
    // Only support string private keys for StaticDataCertificateProvider
    // Custom signing should use InMemoryCertificateProvider
    if (std::holds_alternative<std::string>(pair.private_key)) {
      const std::string& private_key_str =
          std::get<std::string>(pair.private_key);
      grpc_tls_identity_pairs_add_pair(pairs_core, private_key_str.c_str(),
                                       pair.certificate_chain.c_str());
    } else {
      CHECK(false)
          << "StaticDataCertificateProvider does not support custom "
          << "private key signing. Use InMemoryCertificateProvider instead.";
    }
  }
  c_provider_ = grpc_tls_certificate_provider_static_data_create(
      root_certificate.c_str(), pairs_core);
  CHECK_NE(c_provider_, nullptr);
};

StaticDataCertificateProvider::~StaticDataCertificateProvider() {
  grpc_tls_certificate_provider_release(c_provider_);
};

absl::Status StaticDataCertificateProvider::ValidateCredentials() const {
  auto* provider =
      grpc_core::DownCast<grpc_core::StaticDataCertificateProvider*>(
          c_provider_);
  return provider->ValidateCredentials();
}

FileWatcherCertificateProvider::FileWatcherCertificateProvider(
    const std::string& private_key_path,
    const std::string& identity_certificate_path,
    const std::string& root_cert_path, unsigned int refresh_interval_sec) {
  c_provider_ = grpc_tls_certificate_provider_file_watcher_create(
      private_key_path.c_str(), identity_certificate_path.c_str(),
      root_cert_path.c_str(), refresh_interval_sec);
  CHECK_NE(c_provider_, nullptr);
};

FileWatcherCertificateProvider::~FileWatcherCertificateProvider() {
  grpc_tls_certificate_provider_release(c_provider_);
};

absl::Status FileWatcherCertificateProvider::ValidateCredentials() const {
  auto* provider =
      grpc_core::DownCast<grpc_core::FileWatcherCertificateProvider*>(
          c_provider_);
  return provider->ValidateCredentials();
}

// Helper function to convert C++ IdentityKeyCertPair to C-Core PemKeyCertPair
namespace {
grpc_core::PemKeyCertPair ConvertIdentityKeyCertPair(
    IdentityKeyCertPair&& cpp_pair) {
  if (std::holds_alternative<std::string>(cpp_pair.private_key)) {
    // String private key
    return grpc_core::PemKeyCertPair(
        std::get<std::string>(std::move(cpp_pair.private_key)),
        std::move(cpp_pair.certificate_chain));
  } else {
    // Custom signing function
    auto cpp_sign_fn =
        std::get<CustomPrivateKeySign>(std::move(cpp_pair.private_key));
    auto sign_fn = [cpp_sign_fn = std::move(cpp_sign_fn)](
                       absl::string_view data_to_sign,
                       grpc_core::SignatureAlgorithm signature_algorithm,
                       absl::AnyInvocable<void(absl::StatusOr<std::string>)>
                           done_callback) mutable {
      cpp_sign_fn(data_to_sign,
                  static_cast<SignatureAlgorithm>(signature_algorithm),
                  std::move(done_callback));
    };
    return grpc_core::PemKeyCertPair(std::move(sign_fn),
                                     std::move(cpp_pair.certificate_chain));
  }
}

// Overload for const reference (only works with string private keys)
grpc_core::PemKeyCertPair ConvertIdentityKeyCertPair(
    const IdentityKeyCertPair& cpp_pair) {
  CHECK(std::holds_alternative<std::string>(cpp_pair.private_key))
      << "Custom signing functions require move semantics";
  return grpc_core::PemKeyCertPair(std::get<std::string>(cpp_pair.private_key),
                                   cpp_pair.certificate_chain);
}
}  // namespace

// InMemoryCertificateProvider implementation
InMemoryCertificateProvider::InMemoryCertificateProvider(
    std::string root_certificate,
    std::vector<IdentityKeyCertPair> identity_key_cert_pairs) {
  // Convert C++ IdentityKeyCertPair to C-Core PemKeyCertPair using moves
  grpc_core::PemKeyCertPairList core_pairs;
  for (auto& cpp_pair : identity_key_cert_pairs) {
    core_pairs.push_back(ConvertIdentityKeyCertPair(std::move(cpp_pair)));
  }

  // Create the C-Core InMemoryCertificateProvider
  auto core_provider =
      grpc_core::MakeRefCounted<grpc_core::InMemoryCertificateProvider>(
          std::move(root_certificate), std::move(core_pairs));
  c_provider_ = core_provider.release();
  CHECK_NE(c_provider_, nullptr);
}

InMemoryCertificateProvider::~InMemoryCertificateProvider() {
  grpc_tls_certificate_provider_release(c_provider_);
}

std::shared_ptr<InMemoryCertificateProvider>
InMemoryCertificateProvider::Create(
    std::string root_certificate,
    std::vector<IdentityKeyCertPair> identity_key_cert_pairs) {
  return std::shared_ptr<InMemoryCertificateProvider>(
      new InMemoryCertificateProvider(std::move(root_certificate),
                                      std::move(identity_key_cert_pairs)));
}

void InMemoryCertificateProvider::UpdateRootCertificates(
    const std::string& root_certificates) {
  auto* provider =
      grpc_core::DownCast<grpc_core::InMemoryCertificateProvider*>(c_provider_);
  provider->UpdateRootCertificates(root_certificates);
}

void InMemoryCertificateProvider::UpdateIdentityKeyCertPairs(
    std::vector<IdentityKeyCertPair> identity_key_cert_pairs) {
  // Convert C++ IdentityKeyCertPair to C-Core PemKeyCertPair using moves
  grpc_core::PemKeyCertPairList core_pairs;
  for (auto& cpp_pair : identity_key_cert_pairs) {
    core_pairs.push_back(ConvertIdentityKeyCertPair(std::move(cpp_pair)));
  }

  auto* provider =
      grpc_core::DownCast<grpc_core::InMemoryCertificateProvider*>(c_provider_);
  provider->UpdateIdentityKeyCertPairs(std::move(core_pairs));
}

absl::Status InMemoryCertificateProvider::ValidateCredentials() const {
  auto* provider =
      grpc_core::DownCast<grpc_core::InMemoryCertificateProvider*>(c_provider_);
  return provider->ValidateCredentials();
}

}  // namespace experimental
}  // namespace grpc
