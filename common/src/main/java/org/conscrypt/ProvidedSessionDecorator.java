/*
 * Copyright (C) 2017 The Android Open Source Project
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
 * limitations under the License.
 */

package org.conscrypt;

import java.security.Principal;
import java.security.cert.Certificate;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

/**
 * A {@link SessionDecorator} that externalizes the provider of the delegate session. This allows
 * the underlying session to be changed externally.
 */
final class ProvidedSessionDecorator implements SessionDecorator {

  private final Provider provider;

  public ProvidedSessionDecorator(Provider provider) {
    this.provider = provider;
  }

  @Override
  public ConscryptSession getDelegate() {
    return provider.provideSession();
  }

  @Override
  public String getRequestedServerName() {
    return getDelegate().getRequestedServerName();
  }

  @Override
  public List<byte[]> getStatusResponses() {
    return getDelegate().getStatusResponses();
  }

  @Override
  public byte[] getPeerSignedCertificateTimestamp() {
    return getDelegate().getPeerSignedCertificateTimestamp();
  }

  @Override
  public byte[] getId() {
    return getDelegate().getId();
  }

  @Override
  public SSLSessionContext getSessionContext() {
    return getDelegate().getSessionContext();
  }

  @Override
  public long getCreationTime() {
    return getDelegate().getCreationTime();
  }

  @Override
  public long getLastAccessedTime() {
    return getDelegate().getLastAccessedTime();
  }

  @Override
  public void invalidate() {
    getDelegate().invalidate();
  }

  @Override
  public boolean isValid() {
    return getDelegate().isValid();
  }

  @Override
  public void putValue(String s, Object o) {
    getDelegate().putValue(s, o);
  }

  @Override
  public Object getValue(String s) {
    return getDelegate().getValue(s);
  }

  @Override
  public void removeValue(String s) {
    getDelegate().removeValue(s);
  }

  @Override
  public String[] getValueNames() {
    return getDelegate().getValueNames();
  }

  @Override
  public java.security.cert.X509Certificate[] getPeerCertificates()
      throws SSLPeerUnverifiedException {
    return getDelegate().getPeerCertificates();
  }

  @Override
  public Certificate[] getLocalCertificates() {
    return getDelegate().getLocalCertificates();
  }

  @Override
  public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
    return getDelegate().getPeerCertificateChain();
  }

  @Override
  public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
    return getDelegate().getPeerPrincipal();
  }

  @Override
  public Principal getLocalPrincipal() {
    return getDelegate().getLocalPrincipal();
  }

  @Override
  public String getCipherSuite() {
    return getDelegate().getCipherSuite();
  }

  @Override
  public String getProtocol() {
    return getDelegate().getProtocol();
  }

  @Override
  public String getPeerHost() {
    return getDelegate().getPeerHost();
  }

  @Override
  public int getPeerPort() {
    return getDelegate().getPeerPort();
  }

  @Override
  public int getPacketBufferSize() {
    return getDelegate().getPacketBufferSize();
  }

  @Override
  public int getApplicationBufferSize() {
    return getDelegate().getApplicationBufferSize();
  }

  /**
   * The provider of the current delegate session.
   */
  interface Provider {
    ConscryptSession provideSession();
  }
}
