/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package org.conscrypt;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Duck typed implementation of {@link HpkeSpi}.
 * <p>
 * Will wrap any Object which implements all of the methods in HpkeSpi and delegate to them
 * by reflection.
 */
@Internal
public class DuckTypedHpkeSpi implements HpkeSpi {
  private final Object delegate;
  private final Map<String, Method> methods = new HashMap<>();

  private DuckTypedHpkeSpi(Object delegate) throws NoSuchMethodException {
    this.delegate = delegate;

    Class<?> sourceClass = delegate.getClass();
    for (Method targetMethod : HpkeSpi.class.getMethods()) {
      if (targetMethod.isSynthetic()) {
        continue;
      }

      Method sourceMethod =
          sourceClass.getMethod(targetMethod.getName(), targetMethod.getParameterTypes());
      // Check that the return types match too.
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
  public Object getDelegate() {
    return delegate;
  }

  @Override
  public void engineInitSender(
          PublicKey recipientKey, byte[] info, PrivateKey senderKey, byte[] psk, byte[] psk_id)
          throws InvalidKeyException {
    invoke("engineInitSender", recipientKey, info, senderKey, psk, psk_id);
  }

  @Override
  public void engineInitSenderForTesting(PublicKey recipientKey, byte[] info, PrivateKey senderKey,
          byte[] psk, byte[] psk_id, byte[] sKe) throws InvalidKeyException {
    invoke("engineInitSenderForTesting",
            recipientKey, info, senderKey, psk, psk_id, sKe);
  }

  @Override
  public void engineInitRecipient(byte[] encapsulated, PrivateKey key, byte[] info,
          PublicKey senderKey, byte[] psk, byte[] psk_id) throws InvalidKeyException {
    invoke("engineInitRecipient", encapsulated, key, info, senderKey, psk, psk_id);
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
  public byte[] engineOpen(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
    return (byte[]) invoke("engineOpen", ciphertext, aad);
  }

  @Override
  public byte[] getEncapsulated() {
    return (byte[]) invoke("getEncapsulated");
  }
}
