/*
 * Copyright (C) 2021 The Android Open Source Project
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

import org.conscrypt.com.android.net.module.util.DnsPacket;
import org.conscrypt.testing.Streams;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(JUnit4.class)
public class EchInteropTest {

    private static final int TIMEOUT_MILLISECONDS = 30000;

    String[] hostsNonEch = {
            "www.yandex.ru",
            "openstreetmap.org",
            "en.wikipedia.org",
            "web.wechat.com",
            "mirrors.kernel.org",
            "www.google.com",
            "check-tls.akamaized.net", // uses SNI
            "duckduckgo.com", // TLS 1.3
            "deb.debian.org", // TLS 1.3 Fastly
            "tls13.1d.pw", // TLS 1.3 only, no ECH

            "cloudflareresearch.com", // no ECH
            "cloudflare-esni.com", // ESNI no ECH
    };
    String[] hostsEch = {
            "enabled.tls13.com", // TLS 1.3 enabled by Cloudflare with ECH support
            "crypto.cloudflare.com", // ECH

            // ECH enabled
            "draft-13.esni.defo.ie:8413", // OpenSSL s_server
            "draft-13.esni.defo.ie:8414", // OpenSSL s_server, likely forces HRR as it only likes P-384 for TLS =09
            "draft-13.esni.defo.ie:9413", // lighttpd
            "draft-13.esni.defo.ie:10413", // nginx
            "draft-13.esni.defo.ie:11413", // apache
            "draft-13.esni.defo.ie:12413", // haproxy shared mode (haproxy terminates TLS)
            "draft-13.esni.defo.ie:12414", // haproxy split mode (haproxy only decrypts ECH)
    };
    String[] hosts = new String[hostsNonEch.length + hostsEch.length];

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        Security.insertProviderAt(Conscrypt.newProvider(), 1);
        assertTrue(Conscrypt.isAvailable());
        assertTrue(Conscrypt.isConscrypt(SSLContext.getInstance("TLSv1.3")));
        System.arraycopy(hostsNonEch, 0, hosts, 0, hostsNonEch.length);
        System.arraycopy(hostsEch, 0, hosts, hostsNonEch.length, hostsEch.length);
        prefetchDns(hosts);
    }

    @After
    public void tearDown() throws NoSuchAlgorithmException {
        Security.removeProvider("Conscrypt");
        assertFalse(Conscrypt.isConscrypt(SSLContext.getInstance("TLSv1")));
    }

    @Test
    public void testConnectSocket() throws IOException {
        for (String h : hosts) {
            System.out.println("EchInteroptTest " + h + " =================================");
            String[] hostPort = h.split(":");
            String host = hostPort[0];
            int port = 443;
            if (hostPort.length == 2) {
                port = Integer.parseInt(hostPort[1]);
            }

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            assertTrue(Conscrypt.isConscrypt(sslSocketFactory));
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            assertTrue(Conscrypt.isConscrypt(sslSocket));
            boolean setUpEch = false;
            try {
                byte[] echConfigList = TestUtils.readTestFile(h.replace(':', '_') + "-ech-config-list.bin");
                Conscrypt.setUseEchGrease(sslSocket, true);
                Conscrypt.setEchConfigList(sslSocket, echConfigList);
                System.out.println("Enabling ECH Config List and ECH GREASE");
                setUpEch = true;
            } catch (FileNotFoundException e) {
                System.out.println("Enabling ECH GREASE");
                Conscrypt.setUseEchGrease(sslSocket, true);
            }
            sslSocket.setSoTimeout(TIMEOUT_MILLISECONDS);
            sslSocket.startHandshake();
            assertTrue(sslSocket.isConnected());
            AbstractConscryptSocket abstractConscryptSocket = (AbstractConscryptSocket) sslSocket;
            if (setUpEch) {
                assertTrue(abstractConscryptSocket.echAccepted());
            } else {
                assertFalse(abstractConscryptSocket.echAccepted());
            }
            sslSocket.close();
        }
    }

    @Test
    public void testEchRetryConfigWithConnectSocket() throws IOException, NamingException {
        for (String h : hostsEch) {
            System.out.println("EchInteroptTest.testEchRetryConfigWithConnectSocket " + h + " =====================");
            String[] hostPort = h.split(":");
            String host = hostPort[0];
            int port = 443;
            if (hostPort.length == 2) {
                port = Integer.parseInt(hostPort[1]);
            }

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            assertTrue(Conscrypt.isConscrypt(sslSocketFactory));
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            assertTrue(h + " should use Conscrypt", Conscrypt.isConscrypt(sslSocket));

            byte[] echConfigList = getEchConfigListFromDns(h);
            if (echConfigList == null) {
                System.out.println("No ECH Config List found in DNS: " + h);
                continue;
            }
            assertEquals("length should match inline declaration",
                    echConfigList[1] + 2,  // leading 0x00 and length bytes
                    echConfigList.length
            );
            // corrupt the key while leaving the SNI intact
            echConfigList[20] = (byte) 0xff;
            echConfigList[21] = (byte) 0xff;
            echConfigList[22] = (byte) 0xff;
            echConfigList[23] = (byte) 0xff;
            echPbuf("testEchRetryConfigWithConnectSocket corrupted " + h, echConfigList);
            Conscrypt.setEchConfigList(sslSocket, echConfigList);

            try {
                sslSocket.setSoTimeout(TIMEOUT_MILLISECONDS);
                sslSocket.startHandshake();
                sslSocket.close();
                fail("Used corrupt ECH Config List, should not connect to " + h);
            } catch (EchRejectedException e) {
                byte[] echRetryConfig = Conscrypt.getEchRetryConfigList(sslSocket);
                assertNotNull(echRetryConfig);
                sslSocket.close();
                echPbuf("testEchRetryConfigWithConnectSocket getEchRetryConfigList(sslSocket)", echRetryConfig);
                SSLSocket sslSocket2 = (SSLSocket) sslSocketFactory.createSocket(host, port);
                Conscrypt.setEchConfigList(sslSocket2, echRetryConfig);
                sslSocket2.setSoTimeout(TIMEOUT_MILLISECONDS);
                sslSocket2.startHandshake();
                assertTrue(h + " should connect with ECH Retry Config", sslSocket2.isConnected());
                AbstractConscryptSocket abstractConscryptSocket = (AbstractConscryptSocket) sslSocket2;
                assertTrue(h + " should use ECH with Retry Config", abstractConscryptSocket.echAccepted());
                sslSocket2.close();

            } catch (SSLHandshakeException e) {
                System.out.println(e.getMessage().contains(":ECH_REJECTED ") + " | " + e.getMessage());
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
    }

    @Rule
    public ExpectedException echRejectedExceptionRule = ExpectedException.none();

    @Test
    public void testEchConfigOnNonEchHosts() throws IOException {
        for (String h : hostsNonEch) {
            System.out.println("testEchConfigOnNonEchHosts " + h + " ====================================");
            String[] hostPort = h.split(":");
            String host = hostPort[0];
            int port = 443;
            if (hostPort.length == 2) {
                port = Integer.parseInt(hostPort[1]);
            }

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            assertTrue(Conscrypt.isConscrypt(sslSocketFactory));
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            assertTrue(Conscrypt.isConscrypt(sslSocket));

            byte[] echConfigList = TestUtils.readTestFile("draft-13.esni.defo.ie_12414-ech-config-list.bin");
            Conscrypt.setEchConfigList(sslSocket, echConfigList);

            echRejectedExceptionRule.expect(SSLHandshakeException.class);
            echRejectedExceptionRule.expectMessage("ECH_REJECTED");
            sslSocket.setSoTimeout(TIMEOUT_MILLISECONDS);
            sslSocket.startHandshake();
            assertTrue(sslSocket.isConnected());
            AbstractConscryptSocket abstractConscryptSocket = (AbstractConscryptSocket) sslSocket;
            assertTrue(abstractConscryptSocket.echAccepted());
            sslSocket.close();
        }
    }

    @Test
    public void testConnectHttpsURLConnection() throws IOException {
        for (String host : hosts) {
            URL url = new URL("https://" + host);
            System.out.println("EchInteroptTest " + url + " =================================");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            SSLSocketFactory delegateSocketFactory = connection.getSSLSocketFactory();
            assertTrue(Conscrypt.isConscrypt(delegateSocketFactory));
            try {
                byte[] echConfigList = TestUtils.readTestFile(host.replace(':', '_') + "-ech-config-list.bin");
                connection.setSSLSocketFactory(new EchSSLSocketFactory(delegateSocketFactory, echConfigList));
                System.out.println("Enabling ECH Config List and ECH GREASE");
            } catch (FileNotFoundException e) {
                System.out.println("Enabling ECH GREASE");
                connection.setSSLSocketFactory(new EchSSLSocketFactory(delegateSocketFactory, true));
            }
            // Cloudflare will return 403 Forbidden (error code 1010) unless a User Agent is set :-|
            connection.setRequestProperty("User-Agent", "Conscrypt EchInteropTest");
            connection.setConnectTimeout(0); // blocking connect with TCP timeout
            connection.setReadTimeout(0);
            if (connection.getResponseCode() != 200) {
                System.out.println(new String(Streams.readFully(connection.getErrorStream())));
            }
            connection.getContent();
            assertEquals(200, connection.getResponseCode());
            assertEquals("text/html", connection.getContentType().split(";")[0]);
            System.out.println(host + " " + connection.getCipherSuite());
            assertTrue(connection.getCipherSuite().startsWith("TLS"));
            connection.disconnect();
        }
    }

    @Test
    public void testParseDnsAndConnect() throws IOException, NamingException {
        for (String h : hosts) {
            System.out.println("EchInteropTest.testParseDnsAndConnect " + h + " =================================");
            String[] hostPort = h.split(":");
            String host = hostPort[0];
            int port = 443;
            if (hostPort.length > 1) {
                port = Integer.parseInt(hostPort[1]);
            }
            byte[] echConfigList = getEchConfigListFromDns(h);
            if (echConfigList != null) {
                assertEquals("length should match inline declaration",
                        echConfigList[1] + 2,  // leading 0x00 and length bytes
                        echConfigList.length
                );
            }

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            assertTrue(Conscrypt.isConscrypt(sslSocketFactory));
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            assertTrue(Conscrypt.isConscrypt(sslSocket));
            Conscrypt.setUseEchGrease(sslSocket, true);
            if (echConfigList != null) {
                System.out.println("Enabled ECH Config List and ECH GREASE");
            }
            Conscrypt.setEchConfigList(sslSocket, echConfigList);
            sslSocket.setSoTimeout(TIMEOUT_MILLISECONDS);
            sslSocket.startHandshake();
            assertTrue(sslSocket.isConnected());
            AbstractConscryptSocket abstractConscryptSocket = (AbstractConscryptSocket) sslSocket;
            System.out.println(host + " echAccepted " + abstractConscryptSocket.echAccepted());
            if (echConfigList != null) {
                assertTrue(abstractConscryptSocket.echAccepted());
            } else {
                assertFalse(abstractConscryptSocket.echAccepted());
            }
            sslSocket.close();
        }
    }

    @Test
    public void testParseDnsFromFiles() {
        for (String hostString : hosts) {
            System.out.println("EchInteroptTest " + hostString + " =================================");
            String[] h = hostString.split(":");
            String host = h[0];
            if (h.length > 1) {
                if (!"443".equals(h[1])) {
                    host = "_" + h[1] + "._https." + h[0]; // query for non-standard port
                }
            }
            try {
                byte[] dnsAnswer = TestUtils.readTestFile(host + ".bin");
                echPbuf("DNS Answer", dnsAnswer);
                try {
                    DnsEchAnswer dnsEchAnswer = new DnsEchAnswer(dnsAnswer);
                    if (dnsEchAnswer.getEchConfigList() == null) {
                        System.out.println("ECH Config List - null");
                    } else {
                        echPbuf("ECH Config List", dnsEchAnswer.getEchConfigList());
                    }
                } catch (DnsPacket.ParseException e) {
                    e.printStackTrace();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

    static byte[] getEchConfigListFromDns(String hostPort) throws NamingException {
        String[] h = hostPort.split(":");
        String dnshost = h[0];
        if (h.length > 1 && !"443".equals(h[1])) {
            dnshost = "_" + h[1] + "._https." + h[0]; // query for non-standard port
        }

        byte[] echConfigList = null;
        Hashtable<String, String> envProps =
                new Hashtable<String, String>();
        envProps.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.dns.DnsContextFactory");
        DirContext dnsContext = new InitialDirContext(envProps);
        Attributes dnsEntries = dnsContext.getAttributes(dnshost, new String[]{"65"});
        NamingEnumeration<?> ae = dnsEntries.getAll();
        while (ae.hasMore()) {
            Attribute attr = (Attribute) ae.next();
            // only parse SVCB or HTTPS
            if (!("64".equals(attr.getID()) || "65".equals(attr.getID()))) continue;
            for (int i = 0; i < attr.size(); i++) {
                Object rr = attr.get(i);
                if (!(rr instanceof byte[])) continue;
                echConfigList = Conscrypt.getEchConfigListFromDnsRR((byte[]) rr);
            }
        }
        ae.close();
        return echConfigList;
    }

    class DnsEchAnswer extends DnsPacket {
        private static final String TAG = "DnsResolver.DnsAddressAnswer";
        private static final boolean DBG = true;

        /**
         * Service Binding [draft-ietf-dnsop-svcb-https-00]
         */
        public static final int TYPE_SVCB = 64;

        /**
         * HTTPS Binding [draft-ietf-dnsop-svcb-https-00]
         */
        public static final int TYPE_HTTPS = 65;

        private final int mQueryType;

        protected DnsEchAnswer(byte[] data) throws ParseException {
            super(data);
            if ((mHeader.flags & (1 << 15)) == 0) {
                throw new IllegalArgumentException("Not an answer packet");
            }
            if (mHeader.getRecordCount(QDSECTION) == 0) {
                throw new IllegalArgumentException("No question found");
            }
            // Expect only one question in question section.
            mQueryType = mRecords[QDSECTION].get(0).nsType;
        }

        public byte[] getEchConfigList() {
            byte[] results = new byte[0];
            if (mHeader.getRecordCount(ANSECTION) == 0) return results;

            for (final DnsRecord ansSec : mRecords[ANSECTION]) {
                // Only support SVCB and HTTPS since only they can have ECH Config Lists
                int nsType = ansSec.nsType;
                if (nsType != mQueryType || (nsType != TYPE_SVCB && nsType != TYPE_HTTPS)) {
                    continue;
                }
                echPbuf("RR", ansSec.getRR());
                results = Conscrypt.getEchConfigListFromDnsRR(ansSec.getRR());
            }
            return results;
        }
    }

    private static class EchSSLSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final boolean enableEchGrease;

        private byte[] echConfigList;

        public EchSSLSocketFactory(SSLSocketFactory delegate, boolean enableEchGrease) {
            this.delegate = delegate;
            this.enableEchGrease = enableEchGrease;
        }

        public EchSSLSocketFactory(SSLSocketFactory delegate, byte[] echConfigList) {
            this.delegate = delegate;
            this.enableEchGrease = true;
            this.echConfigList = echConfigList;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        @Override
        public Socket createSocket(Socket socket, String host, int port, boolean autoClose)
                throws IOException {
            return setEchSettings(delegate.createSocket(socket, host, port, autoClose));
        }

        @Override
        public Socket createSocket(String host, int port)
                throws IOException, UnknownHostException {
            return setEchSettings(delegate.createSocket(host, port));
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localAddress, int localPort)
                throws IOException, UnknownHostException {
            return setEchSettings(delegate.createSocket(host, port, localAddress, localPort));
        }

        @Override
        public Socket createSocket(InetAddress host, int port)
                throws IOException {
            return setEchSettings(delegate.createSocket(host, port));
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
                throws IOException {
            return setEchSettings(delegate.createSocket(address, port, localAddress, localPort));
        }

        private Socket setEchSettings(Socket socket) {
            SSLSocket sslSocket = (SSLSocket) socket;
            Conscrypt.setUseEchGrease(sslSocket, enableEchGrease);
            Conscrypt.setEchConfigList(sslSocket, echConfigList);
            return sslSocket;
        }

    }

    public static void echPbuf(String msg, byte[] buf) {
        if (buf == null) {
            System.out.println(msg + " ():\n    null");
            return;
        }
        int blen = buf.length;
        System.out.print(msg + " (" + blen + "):\n    ");
        for (int i = 0; i < blen; i++) {
            if ((i != 0) && (i % 16 == 0))
                System.out.print("\n    ");
            System.out.print(String.format("%02x:", Byte.toUnsignedInt(buf[i])));
        }
        System.out.print("\n");
    }

    /**
     * Prime the DNS cache with the hosts that are used in these tests.
     */
    private void prefetchDns(String[] hosts) {
        System.out.println("prefetchDns " + Arrays.toString(hosts));
        for (final String host : hosts) {
            new Thread() {
                @Override
                public void run() {
                    try {
                        InetAddress.getByName(host);
                        getEchConfigListFromDns(host);
                    } catch (UnknownHostException | NamingException e) {
                        // ignored
                    }
                }
            }.start();
        }
    }
}
