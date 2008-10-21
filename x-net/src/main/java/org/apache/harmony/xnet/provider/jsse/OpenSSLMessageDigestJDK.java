package org.apache.harmony.xnet.provider.jsse;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Implements the JDK MessageDigest interface using OpenSSL's EVP API.
 */
public class OpenSSLMessageDigestJDK extends MessageDigest {

    /**
     * Holds a pointer to the native message digest context.
     */
    private int ctx;

    /**
     * Holds a dummy buffer for writing single bytes to the digest.
     */
    private byte[] singleByte = new byte[1];

    /**
     * Creates a new OpenSSLMessageDigestJDK instance for the given algorithm
     * name.
     *  
     * @param algorithm The name of the algorithm, e.g. "SHA1".
     * 
     * @return The new OpenSSLMessageDigestJDK instance.
     * 
     * @throws RuntimeException In case of problems.
     */
    public static OpenSSLMessageDigestJDK getInstance(String algorithm) throws NoSuchAlgorithmException{
        return new OpenSSLMessageDigestJDK(algorithm);
    }

    /**
     * Creates a new OpenSSLMessageDigest instance for the given algorithm
     * name.
     *  
     * @param algorithm The name of the algorithm, e.g. "SHA1".
     */
    private OpenSSLMessageDigestJDK(String algorithm) throws NoSuchAlgorithmException {
        super(algorithm);
        
        ctx = NativeCrypto.EVP_new();
        try {
            NativeCrypto.EVP_DigestInit(ctx, getAlgorithm().replace("-", "").toLowerCase());
        } catch (Exception ex) {
            throw new NoSuchAlgorithmException(ex.getMessage() + " (" + algorithm + ")");
        }
    }
    
    @Override
    protected byte[] engineDigest() {
        byte[] result = new byte[NativeCrypto.EVP_DigestSize(ctx)];
        NativeCrypto.EVP_DigestFinal(ctx, result, 0);
        engineReset();
        return result;
    }

    @Override
    protected void engineReset() {
        NativeCrypto.EVP_DigestInit(ctx, getAlgorithm().replace("-", "").toLowerCase());
    }

    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        NativeCrypto.EVP_DigestUpdate(ctx, input, offset, len);
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        NativeCrypto.EVP_free(ctx);
    }
    
}
