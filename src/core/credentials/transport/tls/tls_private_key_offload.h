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
#include <openssl/ssl.h>

#include <string>

#include "absl/status/statusor.h"
#include "src/core/credentials/transport/tls/ssl_utils.h"
#include "src/core/tsi/transport_security_interface.h"

namespace grpc_core {

// State associated with an SSL object for async private key operations.
struct TlsPrivateKeyOffloadContext {
  CustomPrivateKeySign private_key_sign;
  absl::StatusOr<std::string> signed_bytes;

  // TSI handshake state needed to resume.
  tsi_handshaker* handshaker = nullptr;
  tsi_handshaker_on_next_done_cb notify_cb = nullptr;
  void* notify_user_data = nullptr;
};

// Callback function to be invoked when the user's async sign operation is
// complete. This function is curried with 'ctx' using absl::bind_front.
void TlsOffloadSignDoneCallback(TlsPrivateKeyOffloadContext* ctx,
                                 absl::StatusOr<std::string> signed_data);

// BoringSSL SSL_PRIVATE_KEY_METHOD implementation for TLS private key offloading
extern const SSL_PRIVATE_KEY_METHOD TlsOffloadPrivateKeyMethod;

// Creates and attaches a TlsPrivateKeyOffloadContext to an SSL object
void AttachTlsPrivateKeyOffloadContext(SSL* ssl,
                                        CustomPrivateKeySign private_key_sign,
                                        tsi_handshaker* handshaker);

// Retrieves the TlsPrivateKeyOffloadContext from an SSL object
TlsPrivateKeyOffloadContext* GetTlsPrivateKeyOffloadContext(SSL* ssl);

}  // namespace grpc_core

#endif  // GRPC_SRC_CORE_CREDENTIALS_TRANSPORT_TLS_TLS_PRIVATE_KEY_OFFLOAD_H
