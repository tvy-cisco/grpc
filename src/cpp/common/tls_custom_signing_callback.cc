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

#include "src/cpp/common/tls_custom_signing_callback.h"

#include <grpc/grpc_security.h>
#include <grpcpp/security/tls_credentials_options.h>

namespace grpc {
namespace experimental {

// This file provides type definitions for custom TLS signing callbacks.
// The actual integration with gRPC core TLS requires implementation in:
// - src/core/lib/security/credentials/tls/tls_credentials.h
// - src/core/lib/security/credentials/tls/tls_credentials.cc
// - src/core/tsi/ssl_transport_security.cc
//
// When integrating with the core, the callback stored in TlsCredentialsOptions
// will need to be wrapped with a C-style function pointer that can be passed
// to the SSL/TLS layer (e.g., via SSL_CTX_set_custom_verify_callback or
// similar).

}  // namespace experimental
}  // namespace grpc
