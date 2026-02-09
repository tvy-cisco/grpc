//
// Copyright 2025 gRPC authors.
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

#ifndef GRPC_SRC_CORE_CREDENTIALS_TRANSPORT_TLS_TLS_PRIVATE_KEY_OFFLOAD_H
#define GRPC_SRC_CORE_CREDENTIALS_TRANSPORT_TLS_TLS_PRIVATE_KEY_OFFLOAD_H

#include <grpc/support/port_platform.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <string>

#include "absl/status/statusor.h"
#include "src/core/credentials/transport/tls/ssl_utils.h"
#include "src/core/tsi/transport_security_interface.h"

namespace grpc_core {

// State associated with an EVP_PKEY for custom private key operations.
// This context is stored in the EVP_PKEY's ex_data and allows us to
// intercept signing operations and delegate to the user's callback.
struct TlsPrivateKeyOffloadContext {
  CustomPrivateKeySign private_key_sign;
  absl::StatusOr<std::string> signed_bytes;

  // The original key type (EVP_PKEY_RSA, EVP_PKEY_EC, etc.)
  int key_type = EVP_PKEY_NONE;

  // For RSA: store n and e for public key operations
  BIGNUM* rsa_n = nullptr;
  BIGNUM* rsa_e = nullptr;

  // For EC: store the curve NID and public point
  int ec_curve_nid = 0;
  BIGNUM* ec_pub_x = nullptr;
  BIGNUM* ec_pub_y = nullptr;

  // TSI handshake state needed to resume (for async).
  tsi_handshaker* handshaker = nullptr;
  tsi_handshaker_on_next_done_cb notify_cb = nullptr;
  void* notify_user_data = nullptr;

  ~TlsPrivateKeyOffloadContext();
};

// Creates a custom EVP_PKEY that uses the provided signing function instead
// of a real private key. The public key parameters are extracted from the
// provided PEM certificate chain.
//
// Returns nullptr on failure (e.g., invalid certificate, unsupported key type).
EVP_PKEY* CreateCustomSigningEvpPkey(const char* pem_cert_chain, size_t pem_cert_chain_size,
                                     CustomPrivateKeySign private_key_sign);

// Retrieves the TlsPrivateKeyOffloadContext from an EVP_PKEY (if it has one).
TlsPrivateKeyOffloadContext* GetTlsPrivateKeyOffloadContext(EVP_PKEY* pkey);

// Callback function to be invoked when the user's async sign operation is
// complete. This function is curried with 'ctx' using absl::bind_front.
void TlsOffloadSignDoneCallback(TlsPrivateKeyOffloadContext* ctx,
                                absl::StatusOr<std::string> signed_data);

}  // namespace grpc_core

#endif  // GRPC_SRC_CORE_CREDENTIALS_TRANSPORT_TLS_TLS_PRIVATE_KEY_OFFLOAD_H
