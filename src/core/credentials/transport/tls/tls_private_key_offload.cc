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

#include "src/core/credentials/transport/tls/tls_private_key_offload.h"

#include <grpc/support/port_platform.h>
#include <openssl/ssl.h>

#include <cstring>
#include <memory>
#include <utility>

#include "absl/functional/bind_front.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace grpc_core {

namespace {

// Index for storing TlsPrivateKeyOffloadContext in SSL ex_data
int g_ssl_ex_data_index = -1;

// Initialize the ex_data index (called once)
void InitExDataIndex() {
  if (g_ssl_ex_data_index == -1) {
    g_ssl_ex_data_index = SSL_get_ex_new_index(
        0, nullptr, nullptr, nullptr,
        [](void*, void* ptr, CRYPTO_EX_DATA*, int, long, void*) {
          delete static_cast<TlsPrivateKeyOffloadContext*>(ptr);
        });
  }
}

}  // namespace

void TlsOffloadSignDoneCallback(TlsPrivateKeyOffloadContext* ctx,
                                absl::StatusOr<std::string> signed_data) {
  if (ctx == nullptr) {
    LOG(ERROR) << "TlsOffloadSignDoneCallback called with null context";
    return;
  }

  // Store the result
  ctx->signed_bytes = std::move(signed_data);

  // Notify the TSI layer to re-enter the handshake.
  // This call is thread-safe as per TSI requirements for the callback.
  if (ctx->notify_cb) {
    ctx->notify_cb(ctx->handshaker, ctx->notify_user_data, TSI_OK);
  }
}

// BoringSSL SSL_PRIVATE_KEY_METHOD sign implementation
static enum ssl_private_key_result_t TlsPrivateKeySignWrapper(
    SSL* ssl, uint8_t* out, size_t* out_len, size_t max_out,
    uint16_t signature_algorithm, const uint8_t* in, size_t in_len) {
  if (ssl == nullptr || in == nullptr) {
    return ssl_private_key_failure;
  }

  // Get the TlsPrivateKeyOffloadContext
  TlsPrivateKeyOffloadContext* ctx = GetTlsPrivateKeyOffloadContext(ssl);
  if (ctx == nullptr || !ctx->private_key_sign) {
    LOG(ERROR)
        << "TlsPrivateKeySignWrapper: No offload context or sign function";
    return ssl_private_key_failure;
  }

  // Prepare data to sign
  absl::string_view data_to_sign(reinterpret_cast<const char*>(in), in_len);

  // Create the completion callback by binding the current context
  auto done_callback = absl::bind_front(TlsOffloadSignDoneCallback, ctx);

  // Call the user's async sign function
  // The contract with the user is that they MUST invoke the callback when
  // complete in their implementation, and their impl MUST not block.
  try {
    ctx->private_key_sign(data_to_sign,
                          static_cast<SignatureAlgorithm>(signature_algorithm),
                          std::move(done_callback));
  } catch (...) {
    LOG(ERROR) << "Exception in user's private key sign function";
    return ssl_private_key_failure;
  }

  // Return retry to indicate async operation in progress
  return ssl_private_key_retry;
}

// BoringSSL SSL_PRIVATE_KEY_METHOD complete implementation
static enum ssl_private_key_result_t TlsPrivateKeyOffloadComplete(
    SSL* ssl, uint8_t* out, size_t* out_len, size_t max_out) {
  if (ssl == nullptr) {
    return ssl_private_key_failure;
  }

  // Get TlsPrivateKeyOffloadContext
  TlsPrivateKeyOffloadContext* ctx = GetTlsPrivateKeyOffloadContext(ssl);
  if (ctx == nullptr) {
    LOG(ERROR) << "TlsPrivateKeyOffloadComplete: No offload context";
    return ssl_private_key_failure;
  }

  // Check if we have the signed data
  if (!ctx->signed_bytes.ok()) {
    LOG(ERROR) << "TlsPrivateKeyOffloadComplete: Sign operation failed: "
               << ctx->signed_bytes.status().message();
    return ssl_private_key_failure;
  }

  const std::string& signed_data = *ctx->signed_bytes;

  // Check if output buffer is large enough
  if (signed_data.length() > max_out) {
    LOG(ERROR) << "TlsPrivateKeyOffloadComplete: Output buffer too small";
    return ssl_private_key_failure;
  }

  // Copy signed data to output
  std::memcpy(out, signed_data.data(), signed_data.length());
  *out_len = signed_data.length();

  // Tell BoringSSL we're done
  return ssl_private_key_success;
}

// The SSL_PRIVATE_KEY_METHOD structure
const SSL_PRIVATE_KEY_METHOD TlsOffloadPrivateKeyMethod = {
    TlsPrivateKeySignWrapper,
    nullptr,  // decrypt not implemented for this use case (ECDHE only)
    TlsPrivateKeyOffloadComplete};

void AttachTlsPrivateKeyOffloadContext(SSL* ssl,
                                       CustomPrivateKeySign private_key_sign,
                                       tsi_handshaker* handshaker) {
  InitExDataIndex();

  auto* ctx = new TlsPrivateKeyOffloadContext();
  ctx->private_key_sign = std::move(private_key_sign);
  ctx->handshaker = handshaker;

  SSL_set_ex_data(ssl, g_ssl_ex_data_index, ctx);
  SSL_set_private_key_method(ssl, &TlsOffloadPrivateKeyMethod);
}

TlsPrivateKeyOffloadContext* GetTlsPrivateKeyOffloadContext(SSL* ssl) {
  InitExDataIndex();
  return static_cast<TlsPrivateKeyOffloadContext*>(
      SSL_get_ex_data(ssl, g_ssl_ex_data_index));
}

}  // namespace grpc_core
