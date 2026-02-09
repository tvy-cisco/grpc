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

// OpenSSL 3.x deprecates RSA_METHOD and EC_KEY_METHOD but provides no
// alternative for custom signing callbacks without implementing a full
// provider. We must use the legacy APIs for signing interception.
// This must be defined before any OpenSSL headers are included.
#define OPENSSL_SUPPRESS_DEPRECATED

#include "src/core/credentials/transport/tls/tls_private_key_offload.h"

#include <grpc/support/port_platform.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

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

// EVP_PKEY ex_data index for storing TlsPrivateKeyOffloadContext
int g_evp_pkey_ex_data_index = -1;

// Custom RSA_METHOD and EC_KEY_METHOD (deprecated in OpenSSL 3.x but required
// for custom signing callbacks - no modern alternative without full provider)
RSA_METHOD* g_custom_rsa_method = nullptr;
EC_KEY_METHOD* g_custom_ec_key_method = nullptr;

void InitExDataIndex() {
  if (g_evp_pkey_ex_data_index == -1) {
    g_evp_pkey_ex_data_index = EVP_PKEY_get_ex_new_index(
        0, nullptr, nullptr, nullptr,
        [](void*, void* ptr, CRYPTO_EX_DATA*, int, long, void*) {
          delete static_cast<TlsPrivateKeyOffloadContext*>(ptr);
        });
  }
}

// Get the context from an RSA key
TlsPrivateKeyOffloadContext* GetContextFromRsa(const RSA* rsa) {
  if (rsa == nullptr) return nullptr;
  EVP_PKEY* pkey = static_cast<EVP_PKEY*>(RSA_get_ex_data(rsa, 0));
  if (pkey == nullptr) return nullptr;
  return GetTlsPrivateKeyOffloadContext(pkey);
}

// Get the context from an EC_KEY
TlsPrivateKeyOffloadContext* GetContextFromEcKey(const EC_KEY* ec_key) {
  if (ec_key == nullptr) return nullptr;
  EVP_PKEY* pkey = static_cast<EVP_PKEY*>(EC_KEY_get_ex_data(ec_key, 0));
  if (pkey == nullptr) return nullptr;
  return GetTlsPrivateKeyOffloadContext(pkey);
}

// Custom RSA sign function that delegates to user's callback
int CustomRsaSign(int type, const unsigned char* m, unsigned int m_length,
                  unsigned char* sigret, unsigned int* siglen, const RSA* rsa) {
  TlsPrivateKeyOffloadContext* ctx = GetContextFromRsa(rsa);
  if (ctx == nullptr || !ctx->private_key_sign) {
    LOG(ERROR) << "CustomRsaSign: No context or sign function";
    return 0;
  }

  // For synchronous signing, we call the callback and wait
  // The callback should be invoked synchronously in this path
  absl::string_view data_to_sign(reinterpret_cast<const char*>(m), m_length);

  bool sign_complete = false;
  absl::StatusOr<std::string> result;

  auto done_callback = [&sign_complete,
                        &result](absl::StatusOr<std::string> signed_data) {
    result = std::move(signed_data);
    sign_complete = true;
  };

  // Map OpenSSL NID to SignatureAlgorithm
  // For RSA, the 'type' is the hash algorithm NID
  SignatureAlgorithm sig_alg = SignatureAlgorithm::kRsaPkcs1Sha256;
  switch (type) {
    case NID_sha256:
      sig_alg = SignatureAlgorithm::kRsaPkcs1Sha256;
      break;
    case NID_sha384:
      sig_alg = SignatureAlgorithm::kRsaPkcs1Sha384;
      break;
    case NID_sha512:
      sig_alg = SignatureAlgorithm::kRsaPkcs1Sha512;
      break;
    default:
      LOG(WARNING) << "CustomRsaSign: Unknown hash type " << type
                   << ", defaulting to SHA256";
      break;
  }

  ctx->private_key_sign(data_to_sign, sig_alg, std::move(done_callback));

  if (!sign_complete) {
    LOG(ERROR) << "CustomRsaSign: Sign callback did not complete synchronously";
    return 0;
  }

  if (!result.ok()) {
    LOG(ERROR) << "CustomRsaSign: Sign failed: " << result.status().message();
    return 0;
  }

  if (result->size() > static_cast<size_t>(RSA_size(rsa))) {
    LOG(ERROR) << "CustomRsaSign: Signature too large";
    return 0;
  }

  std::memcpy(sigret, result->data(), result->size());
  *siglen = static_cast<unsigned int>(result->size());
  return 1;
}

// Custom ECDSA sign function
int CustomEcdsaSign(int type, const unsigned char* dgst, int dlen,
                    unsigned char* sig, unsigned int* siglen,
                    const BIGNUM* kinv, const BIGNUM* r, EC_KEY* eckey) {
  (void)kinv;
  (void)r;

  TlsPrivateKeyOffloadContext* ctx = GetContextFromEcKey(eckey);
  if (ctx == nullptr || !ctx->private_key_sign) {
    LOG(ERROR) << "CustomEcdsaSign: No context or sign function";
    return 0;
  }

  absl::string_view data_to_sign(reinterpret_cast<const char*>(dgst), dlen);

  bool sign_complete = false;
  absl::StatusOr<std::string> result;

  auto done_callback = [&sign_complete,
                        &result](absl::StatusOr<std::string> signed_data) {
    result = std::move(signed_data);
    sign_complete = true;
  };

  // Map hash type to SignatureAlgorithm for ECDSA
  SignatureAlgorithm sig_alg = SignatureAlgorithm::kEcdsaSecp256r1Sha256;
  switch (type) {
    case NID_sha256:
      sig_alg = SignatureAlgorithm::kEcdsaSecp256r1Sha256;
      break;
    case NID_sha384:
      sig_alg = SignatureAlgorithm::kEcdsaSecp384r1Sha384;
      break;
    case NID_sha512:
      sig_alg = SignatureAlgorithm::kEcdsaSecp521r1Sha512;
      break;
    default:
      LOG(WARNING) << "CustomEcdsaSign: Unknown hash type " << type;
      break;
  }

  ctx->private_key_sign(data_to_sign, sig_alg, std::move(done_callback));

  if (!sign_complete) {
    LOG(ERROR)
        << "CustomEcdsaSign: Sign callback did not complete synchronously";
    return 0;
  }

  if (!result.ok()) {
    LOG(ERROR) << "CustomEcdsaSign: Sign failed: " << result.status().message();
    return 0;
  }

  std::memcpy(sig, result->data(), result->size());
  *siglen = static_cast<unsigned int>(result->size());
  return 1;
}

// Note: InitCustomRsaMethod and InitCustomEcKeyMethod use deprecated APIs
// (RSA_meth_*, EC_KEY_METHOD_*) because OpenSSL 3.x provides no alternative
// for custom signing callbacks without implementing a full OSSL_PROVIDER.
// The provider API would require ~500+ lines of boilerplate code.

void InitCustomRsaMethod() {
  if (g_custom_rsa_method == nullptr) {
    g_custom_rsa_method = RSA_meth_dup(RSA_get_default_method());
    if (g_custom_rsa_method != nullptr) {
      RSA_meth_set1_name(g_custom_rsa_method, "gRPC Custom RSA Method");
      RSA_meth_set_sign(g_custom_rsa_method, CustomRsaSign);
      // We don't implement private encrypt/decrypt since we only need signing
      RSA_meth_set_priv_enc(g_custom_rsa_method, nullptr);
      RSA_meth_set_priv_dec(g_custom_rsa_method, nullptr);
    }
  }
}

void InitCustomEcKeyMethod() {
  if (g_custom_ec_key_method == nullptr) {
    g_custom_ec_key_method = EC_KEY_METHOD_new(EC_KEY_get_default_method());
    if (g_custom_ec_key_method != nullptr) {
      EC_KEY_METHOD_set_sign(g_custom_ec_key_method, CustomEcdsaSign,
                             nullptr,   // sign_setup
                             nullptr);  // sign_sig
    }
  }
}

// Create a custom RSA key with our signing callback.
// Uses legacy RSA_METHOD because OpenSSL 3.x EVP_PKEY_fromdata creates
// provider-based keys that don't support custom method hooks.
RSA* CreateCustomRsa(EVP_PKEY* pkey, TlsPrivateKeyOffloadContext* ctx) {
  InitCustomRsaMethod();
  if (g_custom_rsa_method == nullptr) {
    LOG(ERROR) << "Failed to create custom RSA method";
    return nullptr;
  }

  RSA* rsa = RSA_new();
  if (rsa == nullptr) {
    return nullptr;
  }

  // Set our custom method
  if (!RSA_set_method(rsa, g_custom_rsa_method)) {
    RSA_free(rsa);
    return nullptr;
  }

  // Set the public key components
  BIGNUM* n = BN_dup(ctx->rsa_n);
  BIGNUM* e = BN_dup(ctx->rsa_e);
  if (n == nullptr || e == nullptr || !RSA_set0_key(rsa, n, e, nullptr)) {
    BN_free(n);
    BN_free(e);
    RSA_free(rsa);
    return nullptr;
  }

  // Store reference to EVP_PKEY in RSA ex_data so we can get context in sign
  // callback
  RSA_set_ex_data(rsa, 0, pkey);

  return rsa;
}

// Create a custom EC_KEY with our signing callback.
// Uses legacy EC_KEY_METHOD because OpenSSL 3.x EVP_PKEY_fromdata creates
// provider-based keys that don't support custom method hooks.
EC_KEY* CreateCustomEcKey(EVP_PKEY* pkey, TlsPrivateKeyOffloadContext* ctx) {
  InitCustomEcKeyMethod();
  if (g_custom_ec_key_method == nullptr) {
    LOG(ERROR) << "Failed to create custom EC_KEY method";
    return nullptr;
  }

  EC_KEY* ec_key = EC_KEY_new_by_curve_name(ctx->ec_curve_nid);
  if (ec_key == nullptr) {
    return nullptr;
  }

  // Set our custom method
  EC_KEY_set_method(ec_key, g_custom_ec_key_method);

  // Create the public point from coordinates
  const EC_GROUP* group = EC_KEY_get0_group(ec_key);
  EC_POINT* pub_point = EC_POINT_new(group);
  if (pub_point == nullptr) {
    EC_KEY_free(ec_key);
    return nullptr;
  }

  if (!EC_POINT_set_affine_coordinates_GFp(group, pub_point, ctx->ec_pub_x,
                                           ctx->ec_pub_y, nullptr)) {
    EC_POINT_free(pub_point);
    EC_KEY_free(ec_key);
    return nullptr;
  }

  if (!EC_KEY_set_public_key(ec_key, pub_point)) {
    EC_POINT_free(pub_point);
    EC_KEY_free(ec_key);
    return nullptr;
  }

  EC_POINT_free(pub_point);

  // Store reference to EVP_PKEY in EC_KEY ex_data
  EC_KEY_set_ex_data(ec_key, 0, pkey);

  return ec_key;
}

// Parse PEM certificate and extract public key info using OpenSSL 3.x APIs
bool ExtractPublicKeyInfo(const char* pem_cert_chain,
                          size_t pem_cert_chain_size,
                          TlsPrivateKeyOffloadContext* ctx) {
  BIO* bio =
      BIO_new_mem_buf(pem_cert_chain, static_cast<int>(pem_cert_chain_size));
  if (bio == nullptr) {
    return false;
  }

  X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);

  if (cert == nullptr) {
    LOG(ERROR) << "Failed to parse certificate";
    return false;
  }

  EVP_PKEY* pub_key = X509_get_pubkey(cert);
  X509_free(cert);

  if (pub_key == nullptr) {
    LOG(ERROR) << "Failed to extract public key from certificate";
    return false;
  }

  ctx->key_type = EVP_PKEY_base_id(pub_key);

  bool success = false;
  if (ctx->key_type == EVP_PKEY_RSA) {
    // Use OpenSSL 3.x EVP_PKEY_get_bn_param for RSA
    BIGNUM* n = nullptr;
    BIGNUM* e = nullptr;
    if (EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_RSA_N, &n) &&
        EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_RSA_E, &e)) {
      ctx->rsa_n = n;
      ctx->rsa_e = e;
      success = true;
    } else {
      if (n != nullptr) BN_free(n);
      if (e != nullptr) BN_free(e);
      LOG(ERROR) << "Failed to extract RSA parameters";
    }
  } else if (ctx->key_type == EVP_PKEY_EC) {
    // Use OpenSSL 3.x APIs for EC key extraction
    char group_name[64] = {0};
    size_t group_name_len = 0;
    BIGNUM* pub_x = nullptr;
    BIGNUM* pub_y = nullptr;

    // Get the curve name
    if (!EVP_PKEY_get_utf8_string_param(pub_key, OSSL_PKEY_PARAM_GROUP_NAME,
                                        group_name, sizeof(group_name),
                                        &group_name_len)) {
      LOG(ERROR) << "Failed to get EC group name";
      EVP_PKEY_free(pub_key);
      return false;
    }
    ctx->ec_curve_nid = OBJ_sn2nid(group_name);
    if (ctx->ec_curve_nid == NID_undef) {
      ctx->ec_curve_nid = OBJ_ln2nid(group_name);
    }

    // Get the public key coordinates
    if (EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_EC_PUB_X, &pub_x) &&
        EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_EC_PUB_Y, &pub_y)) {
      ctx->ec_pub_x = pub_x;
      ctx->ec_pub_y = pub_y;
      success = true;
    } else {
      if (pub_x != nullptr) BN_free(pub_x);
      if (pub_y != nullptr) BN_free(pub_y);
      LOG(ERROR) << "Failed to extract EC public key coordinates";
    }
  } else {
    LOG(ERROR) << "Unsupported key type: " << ctx->key_type;
  }

  EVP_PKEY_free(pub_key);
  return success;
}

}  // namespace

TlsPrivateKeyOffloadContext::~TlsPrivateKeyOffloadContext() {
  if (rsa_n != nullptr) BN_free(rsa_n);
  if (rsa_e != nullptr) BN_free(rsa_e);
  if (ec_pub_x != nullptr) BN_free(ec_pub_x);
  if (ec_pub_y != nullptr) BN_free(ec_pub_y);
}

void TlsOffloadSignDoneCallback(TlsPrivateKeyOffloadContext* ctx,
                                absl::StatusOr<std::string> signed_data) {
  if (ctx == nullptr) {
    LOG(ERROR) << "TlsOffloadSignDoneCallback called with null context";
    return;
  }

  ctx->signed_bytes = std::move(signed_data);

  // For async operations, notify TSI to re-enter handshake
  if (ctx->notify_cb != nullptr) {
    ctx->notify_cb(ctx->handshaker, ctx->notify_user_data, TSI_OK);
  }
}

EVP_PKEY* CreateCustomSigningEvpPkey(const char* pem_cert_chain,
                                     size_t pem_cert_chain_size,
                                     CustomPrivateKeySign private_key_sign) {
  InitExDataIndex();

  // Create and populate context
  auto* ctx = new TlsPrivateKeyOffloadContext();
  ctx->private_key_sign = std::move(private_key_sign);

  // Extract public key info from certificate
  if (!ExtractPublicKeyInfo(pem_cert_chain, pem_cert_chain_size, ctx)) {
    delete ctx;
    return nullptr;
  }

  // Create EVP_PKEY
  EVP_PKEY* pkey = EVP_PKEY_new();
  if (pkey == nullptr) {
    delete ctx;
    return nullptr;
  }

  // Store context in ex_data
  EVP_PKEY_set_ex_data(pkey, g_evp_pkey_ex_data_index, ctx);

  bool success = false;
  if (ctx->key_type == EVP_PKEY_RSA) {
    RSA* rsa = CreateCustomRsa(pkey, ctx);
    if (rsa != nullptr && EVP_PKEY_assign_RSA(pkey, rsa)) {
      success = true;
    } else {
      if (rsa != nullptr) RSA_free(rsa);
    }
  } else if (ctx->key_type == EVP_PKEY_EC) {
    EC_KEY* ec_key = CreateCustomEcKey(pkey, ctx);
    if (ec_key != nullptr && EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
      success = true;
    } else {
      if (ec_key != nullptr) EC_KEY_free(ec_key);
    }
  }

  if (!success) {
    EVP_PKEY_free(pkey);  // This will also free context via ex_data destructor
    return nullptr;
  }

  return pkey;
}

TlsPrivateKeyOffloadContext* GetTlsPrivateKeyOffloadContext(EVP_PKEY* pkey) {
  if (pkey == nullptr) return nullptr;
  InitExDataIndex();
  return static_cast<TlsPrivateKeyOffloadContext*>(
      EVP_PKEY_get_ex_data(pkey, g_evp_pkey_ex_data_index));
}

}  // namespace grpc_core
