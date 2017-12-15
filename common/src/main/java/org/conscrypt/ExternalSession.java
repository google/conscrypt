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
import java.util.HashMap;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

/**
 * An externalized view of the underlying {@link SSLSession} used within a
 * socket/engine. This class provides the caller with a consistent session
 * handle which will continue to be usable regardless of internal changes
 * to the connection.  It does this by delegating calls to the <b>current</b>
 * internal session, which is provided by the session {@code Provider}
 * (i.e. the socket or engine that owns the session).  This allows the provider
 * to switch implementations (for instance, using a JNI implementation to
 * access live values while the connection is open and a set of final values
 * when the connection is closed), even if the caller stores a reference to
 * the session object.
 *
 * <p>This class implements the {@link SSLSession} value API itself, rather
 * than delegating to the provided session, to ensure the caller has a consistent
 * value map, regardless of which internal session is currently being used by the
 * socket/engine.  This class will never call the value API methods on the
 * underlying sessions, so they need not be implemented.
 */
final class ExternalSession implements SessionDecorator {

  // Use an initialcapacity of 2 to keep it small in the average case.
  private final HashMap<String, Object> values = new HashMap<String, Object>(2);
  private final Provider provider;

  public ExternalSession(Provider provider) {
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

  @Override
  public Object getValue(String name) {
    if (name == null) {
      throw new IllegalArgumentException("name == null");
    }
    return values.get(name);
  }

  @Override
  public String[] getValueNames() {
    return values.keySet().toArray(new String[values.size()]);
  }

  @Override
  public void putValue(String name, Object value) {
    if (name == null || value == null) {
      throw new IllegalArgumentException("name == null || value == null");
    }
    Object old = values.put(name, value);
    if (value instanceof SSLSessionBindingListener) {
      ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
    }
    if (old instanceof SSLSessionBindingListener) {
      ((SSLSessionBindingListener) old).valueUnbound(new SSLSessionBindingEvent(this, name));
    }

  }

  @Override
  public void removeValue(String name) {
    if (name == null) {
      throw new IllegalArgumentException("name == null");
    }
    Object old = values.remove(name);
    if (old instanceof SSLSessionBindingListener) {
      SSLSessionBindingListener listener = (SSLSessionBindingListener) old;
      listener.valueUnbound(new SSLSessionBindingEvent(this, name));
    }
  }

  /**
   * The provider of the current delegate session.
   */
  interface Provider {
    ConscryptSession provideSession();
  }
}
