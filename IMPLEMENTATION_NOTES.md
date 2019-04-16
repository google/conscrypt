Conscrypt Implementation Notes
========================================

Conscrypt has made some uncommon implementation choices which it's useful to be
aware of.

## TLS 1.3 Cipher Suites

The supported cipher suites in TLS 1.3 are always enabled.  Attempts to disable
them by omitting them from calls to
[`setEnabledCipherSuites()`](https://docs.oracle.com/javase/9/docs/api/javax/net/ssl/SSLSocket.html#setEnabledCipherSuites-java.lang.String:A-)
are ignored.

## Hostname Verification

Conscrypt's hostname verification (enabled by
[`setEndpointIdentificationAlgorithm("HTTPS")`](https://docs.oracle.com/javase/9/docs/api/javax/net/ssl/SSLParameters.html#setEndpointIdentificationAlgorithm-java.lang.String-))
defers entirely to the hostname verifier.  The default `HostnameVerifier` on
OpenJDK always fails, so a `HostnameVerifier` or `ConscryptHostnameVerifier`
must be set to use hostname verification on OpenJDK.  On Android, the default
`HostnameVerifier` performs [RFC 2818](https://tools.ietf.org/html/rfc2818)
hostname validation, so it will work out of the box.

## AEAD Ciphers

Conscrypt's AEAD ciphers do not support incremental processing (i.e. they will
always return null from calls to
[`update()`](https://docs.oracle.com/javase/9/docs/api/javax/crypto/Cipher.html#update-byte:A-)).
Input is only processed on a call to
[`doFinal()`](https://docs.oracle.com/javase/9/docs/api/javax/crypto/Cipher.html#doFinal--).
This ensures that the caller cannot work with output data before the
authenticator has been processed, but it also means that the input data must be
buffered completely for each operation.  This may necessitate splitting larger
inputs into chunks; see the [BoringSSL
docs](https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html)
for a discussion of important factors in doing so safely.

## OAEP Digests

Conscrypt's OAEP ciphers (eg, `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`) use the
named digest for both the main digest and the MGF1 digest.  This differs from
the behavior of some other providers, including the ones bundled with OpenJDK,
which always use SHA-1 for the MGF1 digest.  For maximum compatibility, you
should use `RSA/ECB/OAEPPadding` and initialize it with an
[`OAEPParameterSpec`](https://docs.oracle.com/javase/9/docs/api/javax/crypto/spec/OAEPParameterSpec.html).
