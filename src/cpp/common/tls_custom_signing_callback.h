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

#ifndef GRPC_SRC_CPP_COMMON_TLS_CUSTOM_SIGNING_CALLBACK_H
#define GRPC_SRC_CPP_COMMON_TLS_CUSTOM_SIGNING_CALLBACK_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace grpc {
namespace experimental {

/// Signature algorithm types used in TLS signing operations
enum class TlsSignatureAlgorithm {
  kRsaPkcs1Sha256 = 0x0401,
  kRsaPkcs1Sha384 = 0x0501,
  kRsaPkcs1Sha512 = 0x0601,
  kEcdsaSecp256r1Sha256 = 0x0403,
  kEcdsaSecp384r1Sha384 = 0x0503,
  kEcdsaSecp521r1Sha512 = 0x0603,
  kRsaPssSha256 = 0x0804,
  kRsaPssSha384 = 0x0805,
  kRsaPssSha512 = 0x0806,
};

/// Result of a signing operation
struct TlsSigningResult {
  /// Success status
  bool success;

  /// Signature data (empty if success is false)
  std::vector<uint8_t> signature;

  /// Error message (empty if success is true)
  std::string error_message;

  TlsSigningResult() : success(false) {}

  static TlsSigningResult Success(const std::vector<uint8_t>& sig) {
    TlsSigningResult result;
    result.success = true;
    result.signature = sig;
    return result;
  }

  static TlsSigningResult Success(const uint8_t* sig, size_t sig_len) {
    TlsSigningResult result;
    result.success = true;
    result.signature.assign(sig, sig + sig_len);
    return result;
  }

  static TlsSigningResult Error(const std::string& error) {
    TlsSigningResult result;
    result.success = false;
    result.error_message = error;
    return result;
  }
};

/// Custom signing callback interface for TLS private key operations.
/// This allows integration with platform-specific key stores like
/// Windows Certificate Store with NCRYPT, HSMs, or other secure
/// key storage mechanisms where the private key cannot be directly accessed.
///
/// Example usage with Windows Certificate Store:
/// ```cpp
/// auto signing_callback = [cert_context](
///     TlsSignatureAlgorithm algorithm,
///     const uint8_t* input, size_t input_len) -> TlsSigningResult {
///
///   NCRYPT_KEY_HANDLE key_handle;
///   DWORD key_spec;
///   BOOL must_free;
///
///   if (!CryptAcquireCertificatePrivateKey(
///       cert_context, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
///       nullptr, &key_handle, &key_spec, &must_free)) {
///     return TlsSigningResult::Error("Failed to acquire private key");
///   }
///
///   // Determine padding and hash algorithm based on signature algorithm
///   BCRYPT_PKCS1_PADDING_INFO padding_info;
///   // ... setup padding based on algorithm ...
///
///   DWORD signature_size = 0;
///   NTSTATUS status = NCryptSignHash(
///       key_handle, &padding_info, (BYTE*)input, input_len,
///       nullptr, 0, &signature_size, BCRYPT_PAD_PKCS1);
///
///   if (status != ERROR_SUCCESS) {
///     if (must_free) NCryptFreeObject(key_handle);
///     return TlsSigningResult::Error("Failed to get signature size");
///   }
///
///   std::vector<uint8_t> signature(signature_size);
///   status = NCryptSignHash(
///       key_handle, &padding_info, (BYTE*)input, input_len,
///       signature.data(), signature_size, &signature_size, BCRYPT_PAD_PKCS1);
///
///   if (must_free) NCryptFreeObject(key_handle);
///
///   if (status != ERROR_SUCCESS) {
///     return TlsSigningResult::Error("Failed to sign hash");
///   }
///
///   signature.resize(signature_size);
///   return TlsSigningResult::Success(signature);
/// };
/// ```
using TlsCustomSigningCallback = std::function<TlsSigningResult(
    TlsSignatureAlgorithm algorithm, const uint8_t* input, size_t input_len)>;

}  // namespace experimental
}  // namespace grpc

#endif  // GRPC_SRC_CPP_COMMON_TLS_CUSTOM_SIGNING_CALLBACK_H
