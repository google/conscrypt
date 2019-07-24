package org.conscrypt.testing;

import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import org.conscrypt.java.security.StandardNames;

/**
 * A provider that supplies and can use keys whose keying material is hidden from callers.
 */
@SuppressWarnings("serial")
public class OpaqueProvider extends Provider {

  public static final String NAME = "OpaqueProvider";

  public OpaqueProvider() {
    super(NAME, 1.0, "test provider");
    put("Signature.NONEwithECDSA", OpaqueSignatureSpi.ECDSA.class.getName());
    put("Cipher.RSA/ECB/NoPadding", OpaqueCipherSpi.NoPadding.class.getName());
    put("Cipher.RSA/ECB/PKCS1Padding", OpaqueCipherSpi.PKCS1Padding.class.getName());
  }

  /**
   * Returns an opaque key that wraps the given key.
   */
  public static PrivateKey wrapKey(PrivateKey key) {
    if (key instanceof RSAPrivateKey) {
      return new OpaqueDelegatingRSAPrivateKey((RSAPrivateKey) key);
    } else if (key instanceof ECPrivateKey) {
      return new OpaqueDelegatingECPrivateKey((ECPrivateKey) key);
    } else {
      fail("Unknown key type: " + key.getClass().getName());
      return null;
    }
  }

  /**
   * Returns an opaque key that wraps the given key and is additionally marked with the
   * appropriate FooPrivateKey interface for that key type.
   */
  public static PrivateKey wrapKeyMarked(PrivateKey key) {
    if (key instanceof RSAPrivateKey) {
      return new OpaqueDelegatingMarkedRSAPrivateKey((RSAPrivateKey) key);
    } else if (key instanceof ECPrivateKey) {
      return new OpaqueDelegatingMarkedECPrivateKey((ECPrivateKey) key);
    } else {
      fail("Unknown key type: " + key.getClass().getName());
      return null;
    }
  }

  private static class OpaqueSignatureSpi extends SignatureSpi {
    private final String algorithm;
    private Signature delegate;

    OpaqueSignatureSpi(String algorithm) {
      this.algorithm = algorithm;
    }

    public final static class ECDSA extends OpaqueSignatureSpi {
      public ECDSA() {
        super("NONEwithECDSA");
      }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
      fail("Cannot verify");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
      DelegatingPrivateKey opaqueKey = (DelegatingPrivateKey) privateKey;
      try {
        delegate = Signature.getInstance(algorithm);
      } catch (NoSuchAlgorithmException e) {
        throw new InvalidKeyException(e);
      }
      delegate.initSign(opaqueKey.getDelegate());
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
      delegate.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
      delegate.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
      return delegate.sign();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
      return delegate.verify(sigBytes);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException {
      delegate.setParameter(param, value);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
      return delegate.getParameter(param);
    }
  }

  private static class OpaqueCipherSpi extends CipherSpi {
    private Cipher delegate;
    private final String algorithm;

    public OpaqueCipherSpi(String algorithm) {
      this.algorithm = algorithm;
    }

    public final static class NoPadding extends OpaqueCipherSpi {
      public NoPadding() {
        super("RSA/ECB/NoPadding");
      }
    }

    public final static class PKCS1Padding extends OpaqueCipherSpi {
      public PKCS1Padding() {
        super("RSA/ECB/PKCS1Padding");
      }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
      fail();
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
      fail();
    }

    @Override
    protected int engineGetBlockSize() {
      return delegate.getBlockSize();
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
      return delegate.getOutputSize(inputLen);
    }

    @Override
    protected byte[] engineGetIV() {
      return delegate.getIV();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
      return delegate.getParameters();
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException {
      getCipher();
      delegate.init(opmode, ((DelegatingPrivateKey) key).getDelegate(), random);
    }

    void getCipher() throws InvalidKeyException {
      try {
        delegate = Cipher.getInstance(algorithm, StandardNames.JSSE_PROVIDER_NAME);
      } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
        throw new InvalidKeyException(e);
      }
    }

    @Override
    protected void engineInit(
        int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
      getCipher();
      delegate.init(opmode, ((DelegatingPrivateKey) key).getDelegate(), params, random);
    }

    @Override
    protected void engineInit(
        int opmode, Key key, AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
      getCipher();
      delegate.init(opmode, ((DelegatingPrivateKey) key).getDelegate(), params, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
      return delegate.update(input, inputOffset, inputLen);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
        int outputOffset) throws ShortBufferException {
      return delegate.update(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException {
      return delegate.doFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(
        byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
      return delegate.doFinal(input, inputOffset, inputLen, output, outputOffset);
    }
  }

  private interface DelegatingPrivateKey { PrivateKey getDelegate(); }

  private static class OpaqueDelegatingECPrivateKey
      implements ECKey, PrivateKey, DelegatingPrivateKey {
    private final ECPrivateKey delegate;

    private OpaqueDelegatingECPrivateKey(ECPrivateKey delegate) {
      this.delegate = delegate;
    }

    @Override
    public PrivateKey getDelegate() {
      return delegate;
    }

    @Override
    public String getAlgorithm() {
      return delegate.getAlgorithm();
    }

    @Override
    public String getFormat() {
      return null;
    }

    @Override
    public byte[] getEncoded() {
      return null;
    }

    @Override
    public ECParameterSpec getParams() {
      return delegate.getParams();
    }
  }

  private static class OpaqueDelegatingMarkedECPrivateKey extends OpaqueDelegatingECPrivateKey
      implements ECPrivateKey {
    private OpaqueDelegatingMarkedECPrivateKey(ECPrivateKey delegate) {
      super(delegate);
    }

    @Override
    public BigInteger getS() {
      throw new UnsupportedOperationException("Nope");
    }
  }

  private static class OpaqueDelegatingRSAPrivateKey
      implements RSAKey, PrivateKey, DelegatingPrivateKey {

    private final RSAPrivateKey delegate;

    private OpaqueDelegatingRSAPrivateKey(RSAPrivateKey delegate) {
      this.delegate = delegate;
    }

    @Override
    public String getAlgorithm() {
      return delegate.getAlgorithm();
    }

    @Override
    public String getFormat() {
      return null;
    }

    @Override
    public byte[] getEncoded() {
      return null;
    }

    @Override
    public BigInteger getModulus() {
      return delegate.getModulus();
    }

    @Override
    public PrivateKey getDelegate() {
      return delegate;
    }
  }

  private static class OpaqueDelegatingMarkedRSAPrivateKey extends OpaqueDelegatingRSAPrivateKey
     implements RSAPrivateKey {
    private OpaqueDelegatingMarkedRSAPrivateKey(RSAPrivateKey delegate) {
      super(delegate);
    }

    @Override
    public BigInteger getPrivateExponent() {
      throw new UnsupportedOperationException("Nope");
    }
  }
}
