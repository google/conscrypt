package org.conscrypt.testing;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * A provider that throws UnsupportedOperationException whenever its features are used.
 */
@SuppressWarnings("serial")
public class BrokenProvider extends Provider {

  public static final String NAME = "BrokenProvider";

  public BrokenProvider() {
    super(NAME, 1.0, "A broken provider");
    put("Signature.NONEwithECDSA", BrokenSignatureSpi.ECDSA.class.getName());
  }

  private static class BrokenSignatureSpi extends SignatureSpi {

    BrokenSignatureSpi() { }

    public final static class ECDSA extends BrokenSignatureSpi {
      public ECDSA() {
        super();
      }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
      throw new UnsupportedOperationException("Nope");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
      throw new UnsupportedOperationException("Nope");
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
      throw new UnsupportedOperationException("Nope");
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
      throw new UnsupportedOperationException("Nope");
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
      throw new UnsupportedOperationException("Nope");
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
      throw new UnsupportedOperationException("Nope");
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException {
      throw new UnsupportedOperationException("Nope");
    }

    @SuppressWarnings("deprecation")
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
      throw new UnsupportedOperationException("Nope");
    }
  }
}
