# Integration Checklist - Windows Certificate Store mTLS

Use this checklist to integrate Windows Certificate Store support into your gRPC C++ project.

## Phase 1: Add Files to Your Project

### Core Files (Required)
- [ ] Copy `common/tls_custom_signing_callback.h` to your gRPC source tree
- [ ] Copy `common/tls_custom_signing_callback.cc` to your gRPC source tree
- [ ] Modify `common/tls_credentials_options.cc` with the changes (add method)

### Example Files (Optional, for reference)
- [ ] Copy `examples/simple_windows_cert_example.cc` (recommended for learning)
- [ ] Copy `examples/minimal_windows_cert_example.cc` (optional)
- [ ] Copy `examples/windows_cert_store_example.cc` (optional - production reference)

### Documentation (Optional, but helpful)
- [ ] Copy `WINDOWS_CERTSTORE_INTEGRATION.md`
- [ ] Copy `IMPLEMENTATION_GUIDE.md`
- [ ] Copy `QUICK_REFERENCE.md`
- [ ] Update `README.md` with Windows cert store section

## Phase 2: Update Build System

### Bazel
- [ ] Add new source files to `BUILD` file
- [ ] Add Windows-specific linkopts:
  ```python
  linkopts = select({
      "@platforms//os:windows": [
          "-DEFAULTLIB:crypt32.lib",
          "-DEFAULTLIB:ncrypt.lib",
          "-DEFAULTLIB:bcrypt.lib",
      ],
      "//conditions:default": [],
  }),
  ```
- [ ] Build and verify no errors: `bazel build //...`

### CMake
- [ ] Add source files to `CMakeLists.txt`:
  ```cmake
  if(WIN32)
    target_sources(grpc++ PRIVATE
      src/cpp/common/tls_custom_signing_callback.cc
    )
    target_link_libraries(grpc++ PRIVATE
      crypt32 ncrypt bcrypt
    )
  endif()
  ```
- [ ] Configure and build: `cmake .. && cmake --build .`
- [ ] Verify no linking errors

### Visual Studio
- [ ] Add `.cc` files to project
- [ ] Add `.h` files to project
- [ ] In Project Properties → Linker → Input → Additional Dependencies, add:
  - `crypt32.lib`
  - `ncrypt.lib`
  - `bcrypt.lib`
- [ ] Build and verify

### Makefile
- [ ] Add object files to build targets
- [ ] Add `-lcrypt32 -lncrypt -lbcrypt` to linker flags (Windows)
- [ ] Test build: `make`

## Phase 3: Prepare Certificates

### For Development
- [ ] Generate test CA certificate:
  ```bash
  openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout ca-key.pem -out ca-cert.pem -days 365 \
    -subj "/CN=Test CA"
  ```
- [ ] Generate client certificate:
  ```bash
  openssl req -newkey rsa:2048 -nodes \
    -keyout client-key.pem -out client-req.pem \
    -subj "/CN=TestClient"
  
  openssl x509 -req -in client-req.pem \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -out client-cert.pem -days 365
  ```
- [ ] Create PFX bundle:
  ```bash
  openssl pkcs12 -export -out client.pfx \
    -inkey client-key.pem -in client-cert.pem \
    -password pass:test123
  ```
- [ ] Import to Windows Certificate Store:
  ```powershell
  certutil -f -user -p test123 -importpfx client.pfx
  ```
- [ ] Verify import:
  ```powershell
  certutil -store MY
  ```

### For Production
- [ ] Obtain certificate from your CA
- [ ] Import certificate with private key to appropriate Windows store
- [ ] Verify certificate has private key:
  ```powershell
  certutil -store -v MY | findstr "Private"
  ```
- [ ] Document certificate subject name for configuration
- [ ] Test private key access (may require admin rights or ACL setup)

## Phase 4: Update Application Code

### Basic Integration
- [ ] Include required headers:
  ```cpp
  #include <grpcpp/security/tls_credentials_options.h>
  #include "src/cpp/common/tls_custom_signing_callback.h"
  #include <windows.h>
  #include <wincrypt.h>
  #include <ncrypt.h>
  ```
- [ ] Load CA certificates (read from file or embed)
- [ ] Find certificate in Windows Certificate Store:
  ```cpp
  HCERTSTORE store = CertOpenSystemStoreA(0, "MY");
  PCCERT_CONTEXT cert = CertFindCertificateInStore(
      store, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_A,
      "CN=YourCertSubject", nullptr);
  CertCloseStore(store, 0);
  ```
- [ ] Convert certificate to PEM and create signing callback (see examples)
- [ ] Setup TLS options:
  ```cpp
  grpc::experimental::TlsChannelCredentialsOptions opts;
  opts.set_custom_signing_callback(signing_callback);
  // ... set certificate provider with cert_pem ...
  ```
- [ ] Create channel with TLS credentials
- [ ] Verify compilation

### Error Handling
- [ ] Check if certificate store opens successfully
- [ ] Check if certificate is found (nullptr check)
- [ ] Handle private key access errors in callback
- [ ] Add appropriate logging
- [ ] Test error paths

### Configuration
- [ ] Make certificate subject name configurable
- [ ] Make certificate store name configurable
- [ ] Make CA certificate path configurable
- [ ] Consider using environment variables or config files

## Phase 5: Testing

### Unit Tests
- [ ] Test certificate store operations
- [ ] Test PEM conversion
- [ ] Test signing callback creation
- [ ] Test error conditions
- [ ] Run all tests: `make test` or `ctest`

### Integration Tests
- [ ] Test connecting to gRPC server with mTLS
- [ ] Test all supported signature algorithms
- [ ] Test with different certificate types (RSA, ECDSA)
- [ ] Test certificate chain validation
- [ ] Test server certificate verification

### Manual Testing
- [ ] Run simple example with test certificate
- [ ] Verify TLS handshake succeeds
- [ ] Verify gRPC calls work correctly
- [ ] Test with production-like certificates
- [ ] Monitor for errors in Windows Event Viewer

### Performance Testing
- [ ] Measure handshake time overhead
- [ ] Test under load
- [ ] Profile NCRYPT signing operations
- [ ] Verify no memory leaks (use memory profiler)

## Phase 6: Documentation

### Code Documentation
- [ ] Add comments to your signing callback implementation
- [ ] Document certificate requirements
- [ ] Document configuration options
- [ ] Add usage examples to README

### User Documentation
- [ ] Document certificate setup procedure
- [ ] Document Windows Certificate Store requirements
- [ ] Create troubleshooting guide
- [ ] Document supported algorithms and limitations

### Internal Documentation
- [ ] Document integration steps for your team
- [ ] Document build process changes
- [ ] Document testing procedures
- [ ] Create runbook for production issues

## Phase 7: Security Review

### Code Review
- [ ] Review signing callback implementation
- [ ] Ensure private keys are never logged
- [ ] Verify proper error handling
- [ ] Check for potential security issues
- [ ] Verify proper resource cleanup

### Configuration Review
- [ ] Ensure server certificate verification is enabled
- [ ] Verify CA certificate bundle is correct
- [ ] Check certificate access permissions
- [ ] Review certificate expiration policies
- [ ] Ensure secure credential storage

### Deployment Review
- [ ] Verify certificates are properly provisioned
- [ ] Check Windows security settings
- [ ] Review ACLs on private keys
- [ ] Test in production-like environment
- [ ] Plan certificate rotation procedure

## Phase 8: Deployment

### Pre-Deployment
- [ ] Test in staging environment
- [ ] Verify all certificates are installed
- [ ] Document rollback procedure
- [ ] Prepare monitoring and alerts
- [ ] Create deployment checklist

### Deployment
- [ ] Deploy updated application
- [ ] Verify TLS handshakes succeed
- [ ] Monitor for errors
- [ ] Check application logs
- [ ] Verify performance metrics

### Post-Deployment
- [ ] Monitor for 24-48 hours
- [ ] Check error rates
- [ ] Verify no certificate-related issues
- [ ] Update documentation with any findings
- [ ] Conduct post-deployment review

## Common Issues & Solutions

### Build Issues
- **Issue**: Undefined symbols for NCRYPT functions
  - **Solution**: Add `ncrypt.lib` to linker libraries

- **Issue**: Header not found
  - **Solution**: Verify include paths in build system

- **Issue**: Compilation errors on non-Windows
  - **Solution**: Ensure `#ifdef _WIN32` guards

### Runtime Issues
- **Issue**: Certificate not found
  - **Solution**: Verify subject name with `certutil -store MY`

- **Issue**: Cannot acquire private key
  - **Solution**: Check certificate has private key marker
  - **Solution**: Verify user has permission to access private key

- **Issue**: TLS handshake fails
  - **Solution**: Enable gRPC logging to see detailed errors
  - **Solution**: Verify CA certificate is correct
  - **Solution**: Check server certificate is valid

### Performance Issues
- **Issue**: Slow handshakes
  - **Solution**: Consider caching NCRYPT key handles
  - **Solution**: Profile signing operations

- **Issue**: High CPU usage
  - **Solution**: Check if software crypto is being used instead of hardware
  - **Solution**: Verify certificate type is appropriate (RSA-2048 recommended)

## Success Criteria

Your integration is successful when:
- ✅ Application builds without errors on Windows
- ✅ Application loads certificates from Windows Certificate Store
- ✅ TLS handshakes complete successfully
- ✅ gRPC calls work correctly over mTLS
- ✅ No private keys are extracted or exposed
- ✅ Performance is acceptable (<50ms handshake overhead)
- ✅ Error handling works correctly
- ✅ Documentation is complete

## Additional Resources

- 📖 [WINDOWS_CERTSTORE_INTEGRATION.md](WINDOWS_CERTSTORE_INTEGRATION.md) - User guide
- 🔧 [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) - Technical details
- 📋 [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Quick reference card
- 💻 [examples/](examples/) - Working code examples
- 🌐 [gRPC Documentation](https://grpc.io/docs/) - Official gRPC docs

## Support Checklist

Before asking for help, verify:
- [ ] Using Windows 10 or later
- [ ] All required libraries are linked
- [ ] Certificate is successfully imported to Windows store
- [ ] Certificate has private key access
- [ ] Reviewed documentation and examples
- [ ] Checked Windows Event Viewer for errors
- [ ] Enabled gRPC debug logging

## Next Steps

After successful integration:
1. Consider contributing improvements back to gRPC
2. Share your experience with the community
3. Document any Edge cases or issues you encountered
4. Help update this checklist with your findings

---

**Target Completion Time**: 4-8 hours (including testing)  
**Difficulty Level**: Intermediate  
**Prerequisites**: Windows development environment, gRPC knowledge, basic certificate understanding
