package org.conscrypt;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class DuckTypedHpkeSpi implements HpkeSpi {
  private final Object delegate;
  private final Map<String, Method> methods = new HashMap<>();

  private DuckTypedHpkeSpi(Object delegate) throws NoSuchMethodException {
    this.delegate = delegate;

    for (Method targetMethod : HpkeSpi.class.getMethods()) {
      if (targetMethod.isSynthetic()) {
        continue;
      }
      Class<?> sourceClass = delegate.getClass();

      Method sourceMethod =
          sourceClass.getMethod(targetMethod.getName(), targetMethod.getParameterTypes());
      // Check that the return type of obj's method matches the target method.
      Class<?> sourceReturnType = sourceMethod.getReturnType();
      Class<?> targetReturnType = targetMethod.getReturnType();
      if (!targetReturnType.isAssignableFrom(sourceReturnType)) {
        throw new NoSuchMethodException(sourceMethod + " return value (" + sourceReturnType
            + ") incompatible with target return value (" + targetReturnType + ")");
      }
      methods.put(sourceMethod.getName(), sourceMethod);
    }
  }

  public static DuckTypedHpkeSpi newInstance(Object delegate) {
    try {
      return new DuckTypedHpkeSpi(delegate);
    } catch (Exception ignored) {
      return null;
    }
  }

  private Object invoke(String methodName, Object... args) {
    Method method = methods.get(methodName);
    if (method == null) {
      throw new IllegalStateException("DuckTypedHpkSpi internal error");
    }
    try {
      return method.invoke(delegate, args);
    } catch (InvocationTargetException | IllegalAccessException e) {
      throw new IllegalStateException("DuckTypedHpkSpi internal error", e);
    }
  }

  // Visible for testing
  Object getDelegate() {
    return delegate;
  }

  @Override
  public void engineInitSender(int mode, PublicKey key, byte[] info, byte[] sKe) {
    invoke("engineInitSender", mode, key, info, sKe);
  }

  @Override
  public void engineInitRecipient(int mode, byte[] enc, PrivateKey key, byte[] info) {
    invoke("engineInitRecipient", mode, enc, key, info);
  }

  @Override
  public byte[] engineSeal(byte[] plaintext, byte[] aad) {
    return (byte[]) invoke("engineSeal", plaintext, aad);
  }

  @Override
  public byte[] engineExport(int length, byte[] exporterContext) {
    return (byte[]) invoke("engineExport", length, exporterContext);
  }

  @Override
  public byte[] engineOpen(byte[] ciphertext, byte[] aad) {
    return (byte[]) invoke("engineOpen", ciphertext, aad);
  }

  @Override
  public byte[] getEnc() {
    return (byte[]) invoke("getEnc");
  }

  @Override
  public Provider getProvider() {
    return (Provider) invoke("getProvider");
  }
}
