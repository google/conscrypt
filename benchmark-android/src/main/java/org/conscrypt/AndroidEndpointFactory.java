package org.conscrypt;

import java.io.IOException;
import java.security.Provider;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

/**
 * Utility for creating test client and server instances.
 */
@SuppressWarnings("ImmutableEnumChecker")
public enum AndroidEndpointFactory implements EndpointFactory {
  @SuppressWarnings("unused")
  CONSCRYPT(newConscryptFactories(false)),
  CONSCRYPT_ENGINE(newConscryptFactories(true));

  private final Factories factories;

  AndroidEndpointFactory(Factories factories) {
    this.factories = factories;
  }

  @Override
  public ClientEndpoint newClient(ChannelType channelType, int port, String[] protocols,
      String[] ciphers) throws IOException {
    return new ClientEndpoint(
        factories.clientFactory, channelType, port, protocols, ciphers);
  }

  @Override
  public ServerEndpoint newServer(ChannelType channelType, int messageSize,
      String[] protocols, String[] ciphers) throws IOException {
    return new ServerEndpoint(factories.serverFactory, factories.serverSocketFactory,
        channelType, messageSize, protocols, ciphers);
  }

  private static final class Factories {
    final SSLSocketFactory clientFactory;
    final SSLSocketFactory serverFactory;
    final SSLServerSocketFactory serverSocketFactory;

    private Factories(SSLSocketFactory clientFactory, SSLSocketFactory serverFactory,
        SSLServerSocketFactory serverSocketFactory) {
      this.clientFactory = clientFactory;
      this.serverFactory = serverFactory;
      this.serverSocketFactory = serverSocketFactory;
    }
  }

  private static Factories newConscryptFactories(boolean useEngineSocket) {
    Provider provider = TestUtils.getConscryptProvider();
    SSLContext clientContext = TestUtils.newClientSslContext(provider);
    SSLContext serverContext = TestUtils.newServerSslContext(provider);
    final SSLSocketFactory clientFactory = clientContext.getSocketFactory();
    final SSLSocketFactory serverFactory = serverContext.getSocketFactory();
    final SSLServerSocketFactory serverSocketFactory = serverContext.getServerSocketFactory();
    TestUtils.setUseEngineSocket(clientFactory, useEngineSocket);
    TestUtils.setUseEngineSocket(serverFactory, useEngineSocket);
    TestUtils.setUseEngineSocket(serverSocketFactory, useEngineSocket);
    return new Factories(clientFactory, serverFactory, serverSocketFactory);
  }
}
