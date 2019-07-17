Conscrypt's Capabilities
========================================

Conscrypt is relatively selective in choosing the set of primitives to provide, focusing
on the most important and widely-used algorithms.  Following is a list of JCA algorithm names
and other identifiers that are supported by Conscrypt.

## TLS

### Protocol Versions

* `SSLv3` (ignored)
* `TLSv1`
* `TLSv1.1`
* `TLSv1.2`
* `TLSv1.3`

Conscrypt supports TLS v1.0-1.3.  For backwards compatibility it will accept
`SSLv3` in calls to methods like
[`setEnabledProtocols()`](https://docs.oracle.com/javase/9/docs/api/javax/net/ssl/SSLSocket.html#setEnabledProtocols-java.lang.String:A-)
but will ignore it.

### SSLContext

* `Default`
* `SSL`
* `TLS`
* `TLSv1`
* `TLSv1.1`
* `TLSv1.2`
* `TLSv1.3`

Conscrypt provides the above set of SSLContext algorithm names for JSSE
purposes, including the special value `Default`, which is used to determine the
value of
[`SSLContext.getDefault()`](https://docs.oracle.com/javase/9/docs/api/javax/net/ssl/SSLContext.html#getDefault--).
The `Default`, `SSL`, `TLS`, and `TLSv1.3` values return a context where TLS
v1.0-1.3 are all enabled; the others return a context with TLS v1.0-1.2 enabled.

### Cipher Suites

#### Enabled
* TLS 1.0-1.2
  * `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`
  * `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
  * `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`
  * `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
  * `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
  * `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`
  * `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
  * `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`
  * `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  * `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
  * `TLS_RSA_WITH_AES_128_CBC_SHA`
  * `TLS_RSA_WITH_AES_128_GCM_SHA256`
  * `TLS_RSA_WITH_AES_256_CBC_SHA`
  * `TLS_RSA_WITH_AES_256_GCM_SHA384`
* TLS 1.3
  * `TLS_AES_128_GCM_SHA256`
  * `TLS_AES_256_GCM_SHA384`
  * `TLS_CHACHA20_POLY1305_SHA256`

The above cipher suites are enabled by default when the associated version of
the protocol is enabled.  The TLS 1.3 cipher suites cannot be customized; they
are always enabled when TLS 1.3 is enabled, and any attempt to disable them via
a call to
[`setEnabledCipherSuites()`](https://docs.oracle.com/javase/9/docs/api/javax/net/ssl/SSLSocket.html#setEnabledCipherSuites-java.lang.String:A-)
is ignored.

#### Supported But Not Enabled
* TLS 1.0-1.2
  * `SSL_RSA_WITH_3DES_EDE_CBC_SHA`
  * `TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA`
  * `TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA`
  * `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256`
  * `TLS_PSK_WITH_AES_128_CBC_SHA`
  * `TLS_PSK_WITH_AES_256_CBC_SHA`

The above cipher suites are supported, but not enabled by default.  TLS 1.3
cipher suites cannot be customized, so there are no cipher suites that are
supported but not enabled.

## Cryptography

### Cipher

* `AES/CBC/NoPadding`
* `AES/CBC/PKCS5Padding`
* `AES/CTR/NoPadding`
* `AES/ECB/NoPadding`
* `AES/ECB/PKCS5Padding`

AES with 128, 192, or 256-bit keys.

* `AES/GCM/NoPadding`

AES/GCM with 128 or 256-bit keys.

* `AES_128/CBC/NoPadding`
* `AES_128/CBC/PKCS5Padding`
* `AES_128/ECB/NoPadding`
* `AES_128/ECB/PKCS5Padding`
* `AES_128/GCM/NoPadding`
* `AES_256/CBC/NoPadding`
* `AES_256/CBC/PKCS5Padding`
* `AES_256/ECB/NoPadding`
* `AES_256/ECB/PKCS5Padding`
* `AES_256/GCM/NoPadding`

Key-restricted versions of the AES ciphers.

* `ARC4`

The RC4 stream cipher.

* `ChaCha20/NONE/NoPadding`
* `ChaCha20/Poly1305/NoPadding`

ChaCha with 20 rounds, 96-bit nonce, and 32-bit counter as described in
[RFC 7539](https://tools.ietf.org/html/rfc7539), either with or without a Poly1305 AEAD
authenticator.

* `DESEDE/CBC/NoPadding`
* `DESEDE/CBC/PKCS5Padding`

Triple DES with either two or three intermediate keys.

* `RSA/ECB/NoPadding`
* `RSA/ECB/OAEPPadding`
* `RSA/ECB/OAEPWithSHA-1AndMGF1Padding`
* `RSA/ECB/OAEPWithSHA-224AndMGF1Padding`
* `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`
* `RSA/ECB/OAEPWithSHA-384AndMGF1Padding`
* `RSA/ECB/OAEPWithSHA-512AndMGF1Padding`
* `RSA/ECB/PKCS1Padding`

Conscrypt's OAEP ciphers (eg, `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`) use the named digest for
both the main digest and the MGF1 digest.  This differs from the behavior of some other
providers, including the ones bundled with OpenJDK, which always use SHA-1 for the MGF1 digest.
For maximum compatibility, you should use `RSA/ECB/OAEPPadding` and initialize it with an
[`OAEPParameterSpec`](https://docs.oracle.com/javase/9/docs/api/javax/crypto/spec/OAEPParameterSpec.html).

### AlgorithmParameters
* `AES`
* `ChaCha20`
* `DESEDE`
* `EC`
* `GCM`
* `OAEP`
* `PSS`

Conscrypt's EC AlgorithmParameters implementation only supports named curves.

### CertificateFactory
* `X509`

### KeyAgreement
* `ECDH`

### KeyFactory
* `EC`
* `RSA`

### KeyGenerator
* `AES`
* `ARC4`
* `ChaCha20`
* `DESEDE`
* `HmacMD5`
* `HmacSHA1`
* `HmacSHA224`
* `HmacSHA256`
* `HmacSHA384`
* `HmacSHA512`

### KeyPairGenerator
* `EC`
* `RSA`

### Mac
* `HmacMD5`
* `HmacSHA1`
* `HmacSHA224`
* `HmacSHA256`
* `HmacSHA384`
* `HmacSHA512`

### MessageDigest
* `MD5`
* `SHA-1`
* `SHA-224`
* `SHA-256`
* `SHA-384`
* `SHA-512`

### SecretKeyFactory
* `DESEDE`

### SecureRandom
* `SHA1PRNG`

### Signature
* `MD5withRSA`
* `NONEwithECDSA`
* `NONEwithRSA`
* `SHA1withRSA`
* `SHA1withECDSA`
* `SHA1withRSA/PSS`
* `SHA224withRSA`
* `SHA224withECDSA`
* `SHA224withRSA/PSS`
* `SHA256withRSA`
* `SHA256withECDSA`
* `SHA256withRSA/PSS`
* `SHA384withRSA`
* `SHA384withECDSA`
* `SHA384withRSA/PSS`
* `SHA512withRSA`
* `SHA512withECDSA`
* `SHA512withRSA/PSS`

### Elliptic Curves

Conscrypt supports the following curves in EC crypto operations (such as ECDSA signatures) and TLS:

| Curve | EC Crypto |  TLS  |
| ----- | :-------: | :---: |
| secp224r1 | X |   |
| prime256v1<br/>(aka secp256r1) | X | X |
| secp384r1 | X | X |
| secp521r1 | X |   |
| x25519 |   | X |
