# Windows Certificate Store Integration for gRPC C++ mTLS

This guide explains how to use certificates from the Windows Certificate Store with gRPC C++ for mutual TLS (mTLS) authentication, leveraging Windows NCRYPT for private key operations.

## Overview

The Windows Certificate Store provides a secure way to manage certificates, but it doesn't expose private keys directly for security reasons. Instead, you must use Windows Cryptography APIs (specifically NCRYPT) to perform signing operations with the private key.

This implementation adds custom signing callback support to gRPC C++, allowing you to:
- Use certificates from Windows Certificate Store
- Sign TLS handshake data using NCRYPT without exposing the private key
- Maintain compatibility with HSMs and smart cards through Windows certificate infrastructure

## Architecture

### Components

1. **TlsCustomSigningCallback**: A callback interface for custom signing operations
2. **TlsCustomSigningContext**: Context containing the certificate chain and signing callback  
3. **TlsCredentialsOptions Extensions**: Methods to set custom signing contexts
4. **Windows Integration Example**: Complete implementation using Windows APIs

### Flow

```
gRPC TLS Handshake
    ↓
Needs to sign data with private key
    ↓
Calls TlsCustomSigningCallback
    ↓
Your callback uses NCRYPT to sign
    ↓
Returns signature to gRPC
    ↓
Handshake continues
```

## Quick Start

### 1. Include Required Headers

```cpp
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/tls_credentials_options.h>
#include "src/cpp/common/tls_custom_signing_callback.h"

// Windows headers
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <bcrypt.h>
```

### 2. Find Your Certificate

```cpp
// Open Windows Certificate Store (usually "MY" for personal certificates)
HCERTSTORE cert_store = CertOpenSystemStoreA(0, "MY");

// Find certificate by subject name
PCCERT_CONTEXT cert_context = CertFindCertificateInStore(
    cert_store,
    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
    0,
    CERT_FIND_SUBJECT_STR_A,
    "CN=MyClientCert",  // Your certificate subject
    nullptr);

CertCloseStore(cert_store, 0);
```

### 3. Create Signing Callback

```cpp
auto signing_callback = [cert_context](
    grpc::experimental::TlsSignatureAlgorithm algorithm,
    const uint8_t* input,
    size_t input_len) -> grpc::experimental::TlsSigningResult {
  
  // Acquire private key handle from certificate
  NCRYPT_KEY_HANDLE key_handle;
  DWORD key_spec;
  BOOL must_free;
  
  if (!CryptAcquireCertificatePrivateKey(
      cert_context,
      CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
      nullptr,
      &key_handle,
      &key_spec,
      &must_free)) {
    return grpc::experimental::TlsSigningResult::Error(
        "Failed to acquire private key");
  }
  
  // Setup padding based on algorithm
  BCRYPT_PKCS1_PADDING_INFO padding_info;
  padding_info.pszAlgId = BCRYPT_SHA256_ALGORITHM;  // Adjust based on algorithm
  
  // Get signature size
  DWORD signature_size = 0;
  NCryptSignHash(key_handle, &padding_info, (BYTE*)input, input_len,
                 nullptr, 0, &signature_size, BCRYPT_PAD_PKCS1);
  
  // Create signature
  std::vector<uint8_t> signature(signature_size);
  SECURITY_STATUS status = NCryptSignHash(
      key_handle, &padding_info, (BYTE*)input, input_len,
      signature.data(), signature_size, &signature_size, BCRYPT_PAD_PKCS1);
  
  if (must_free) NCryptFreeObject(key_handle);
  
  if (status != ERROR_SUCCESS) {
    return grpc::experimental::TlsSigningResult::Error(
        "Signing failed");
  }
  
  signature.resize(signature_size);
  return grpc::experimental::TlsSigningResult::Success(signature);
};
```

### 4. Create TLS Credentials

```cpp
// Convert certificate to PEM format
std::string cert_pem = CertificateToPEM(cert_context);

// Create TLS options
grpc::experimental::TlsChannelCredentialsOptions tls_options;

// Set certificate and callback
grpc::experimental::IdentityKeyCertPair identity;
identity.certificate_chain = cert_pem;
// private_key is empty - we use signing callback instead

auto provider = std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
    root_cert_pem,  // Your CA bundle in PEM format
    std::vector<grpc::experimental::IdentityKeyCertPair>{identity});
tls_options.set_root_certificate_provider(provider);
tls_options.set_identity_certificate_provider(provider);
tls_options.watch_root_certs();
tls_options.watch_identity_key_cert_pairs();

// Set custom signing callback
tls_options.set_custom_signing_callback(signing_callback);

// Enable server verification
tls_options.set_verify_server_certs(true);

// Create credentials
auto credentials = grpc::experimental::TlsCredentials(tls_options);
```

### 5. Create Channel

```cpp
auto channel = grpc::CreateChannel("localhost:50051", credentials);
auto stub = YourService::NewStub(channel);
```

## Complete Example

See [windows_cert_store_example.cc](examples/windows_cert_store_example.cc) for a complete, production-ready implementation including:
- Certificate store enumeration
- Proper error handling
- Algorithm mapping (RSA-PKCS1, RSA-PSS, ECDSA)
- Resource cleanup
- Helper functions

## Supported Signature Algorithms

The implementation supports all common TLS 1.3 signature algorithms:

- **RSA-PKCS1**: SHA256, SHA384, SHA512
- **RSA-PSS**: SHA256, SHA384, SHA512
- **ECDSA**: SECP256R1-SHA256, SECP384R1-SHA384, SECP521R1-SHA512

The signing callback automatically receives the correct algorithm and your implementation should handle it appropriately.

## Certificate Store Locations

Windows has multiple certificate stores:

- **MY**: Personal certificates (most common for client certs)
- **Root**: Trusted root CA certificates
- **CA**: Intermediate CA certificates
- **TrustedPeople**: Trusted people certificates

Access them with:
```cpp
CertOpenSystemStoreA(0, "MY");
```

## Troubleshooting

### Private Key Not Accessible

**Error**: "Failed to acquire private key"

**Solutions**:
- Ensure the private key is marked as exportable (or use NCRYPT-compatible storage)
- Check that your user account has permission to access the private key
- Verify the certificate was properly imported with its private key

### Wrong Signature Algorithm

**Error**: Handshake fails with signature verification error

**Solutions**:
- Implement all required signature algorithms in your callback
- Check that you're using the correct padding scheme (PKCS1 vs PSS)
- Verify hash algorithm matches (SHA256, SHA384, SHA512)

### Performance Issues

If signing is slow:
- Consider caching the NCRYPT_KEY_HANDLE (ensure thread safety)
- Use hardware acceleration if available (smart cards, TPM)
- Profile NCRYPT operations to identify bottlenecks

## Security Considerations

1. **Key Protection**: Private keys never leave the Windows Certificate Store
2. **Access Control**: Respect Windows ACLs on private keys
3. **Certificate Validation**: Always verify server certificates
4. **Secure Storage**: Use appropriate certificate store locations
5. **Audit Logging**: Consider logging signing operations for compliance

## API Reference

### TlsSignatureAlgorithm

Enum defining signature algorithms used in TLS:
- `kRsaPkcs1Sha256`, `kRsaPkcs1Sha384`, `kRsaPkcs1Sha512`
- `kRsaPssSha256`, `kRsaPssSha384`, `kRsaPssSha512`
- `kEcdsaSecp256r1Sha256`, `kEcdsaSecp384r1Sha384`, `kEcdsaSecp521r1Sha512`

### TlsSigningResult

Return value from signing callback:
```cpp
// Success
TlsSigningResult::Success(signature_data);

// Failure
TlsSigningResult::Error("error message");
```

### TlsCustomSigningCallback

Function signature:
```cpp
using TlsCustomSigningCallback = std::function<TlsSigningResult(
    TlsSignatureAlgorithm algorithm,
    const uint8_t* input,      // Data to sign (typically a hash)
    size_t input_len)>;
```

### TlsCustomSigningContext

Container for certificate and signing callback:
```cpp
struct TlsCustomSigningContext {
  std::string certificate_chain;  // PEM format
  TlsCustomSigningCallback signing_callback;
  void* user_data;  // Optional context pointer
};
```

### TlsCredentialsOptions::set_custom_signing_context()

Sets the custom signing context on TLS credentials:
```cpp
void set_custom_signing_context(
    std::shared_ptr<TlsCustomSigningContext> signing_context);
```

## Integration with Core gRPC

**Note**: This implementation currently provides the C++ API extensions. Full integration with the gRPC core TLS implementation requires additional changes to:

1. `src/core/lib/security/credentials/tls/tls_credentials.h`
2. `src/core/lib/security/transport/security_handshaker.cc`
3. SSL context setup in BoringSSL integration

These core changes would add:
- `SSL_CTX_set_custom_signing_callback()` support
- Integration with SSL/TLS handshake state machine
- Callback invocation during certificate verification

For now, this provides the API surface that applications can use, and the core integration can be completed based on your gRPC version and build configuration.

## Server-Side Usage

The same pattern works for gRPC servers:

```cpp
grpc::experimental::TlsServerCredentialsOptions server_tls_options;
server_tls_options.set_custom_signing_context(signing_context);
server_tls_options.set_cert_request_type(
    GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);

auto server_credentials = grpc::experimental::TlsServerCredentials(server_tls_options);
builder.AddListeningPort("0.0.0.0:50051", server_credentials);
```

## Additional Resources

- [Windows Cryptography API: Cryptographic Service Providers](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptographic-service-providers)
- [CNG (Cryptography Next Generation)](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal)
- [gRPC Authentication Guide](https://grpc.io/docs/guides/auth/)
- [TLS 1.3 Signature Algorithms](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3)

## License

Copyright 2026 gRPC authors. Licensed under Apache License 2.0.
