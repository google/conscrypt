package org.conscrypt;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Implements the JDK Signature interface needed for RAW ECDSA signature
 * generation and verification using BoringSSL.
 *
 * @hide
 */
@Internal
public class OpenSSLSignatureRawECDSA extends SignatureSpi {
    /**
     * The current OpenSSL key we're operating on.
     */
    private OpenSSLKey key;

    /**
     * Buffer to hold value to be signed or verified.
     */
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    @Override
    protected void engineUpdate(byte input) {
        buffer.write(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        buffer.write(input, offset, len);
    }

    @Override
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    private static OpenSSLKey verifyKey(OpenSSLKey key) throws InvalidKeyException {
        int pkeyType = NativeCrypto.EVP_PKEY_type(key.getNativeRef());
        if (pkeyType != NativeConstants.EVP_PKEY_EC) {
            throw new InvalidKeyException("Non-EC key used to initialize EC signature.");
        }
        return key;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        key = verifyKey(OpenSSLKey.fromPrivateKey(privateKey));
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        key = verifyKey(OpenSSLKey.fromPublicKey(publicKey));
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (key == null) {
            // This can't actually happen, but you never know...
            throw new SignatureException("No key provided");
        }

        int output_size = NativeCrypto.ECDSA_size(key.getNativeRef());
        byte[] outputBuffer = new byte[output_size];
        try {
            int bytes_written =
                    NativeCrypto.ECDSA_sign(buffer.toByteArray(), outputBuffer, key.getNativeRef());
            if (bytes_written < 0) {
                throw new SignatureException("Could not compute signature.");
            }
            // There's no guarantee that the signature will be ECDSA_size bytes long,
            // that's just the maximum possible length of a signature.  Only return the bytes
            // that were actually produced.
            if (bytes_written != output_size) {
                byte[] newBuffer = new byte[bytes_written];
                System.arraycopy(outputBuffer, 0, newBuffer, 0, bytes_written);
                outputBuffer = newBuffer;
            }
            return outputBuffer;
        } catch (Exception ex) {
            throw new SignatureException(ex);
        } finally {
            buffer.reset();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (key == null) {
            // This can't actually happen, but you never know...
            throw new SignatureException("No key provided");
        }

        try {
            int result =
                    NativeCrypto.ECDSA_verify(buffer.toByteArray(), sigBytes, key.getNativeRef());
            if (result == -1) {
                throw new SignatureException("Could not verify signature.");
            }
            return result == 1;
        } catch (Exception ex) {
            throw new SignatureException(ex);
        } finally {
            buffer.reset();
        }
    }
}
