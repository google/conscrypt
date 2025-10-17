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
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;

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

    private static String[] hostsNonEch = {
            "www.yandex.ru",
            "en.wikipedia.org",
            // TEMP - causes prefetch exception "web.wechat.com",
            "mirrors.kernel.org",
            "www.google.com",
            "check-tls.akamaized.net",    // uses SNI
            "duckduckgo.com",             // TLS 1.3
            "deb.debian.org",             // TLS 1.3 Fastly
            "tls13.1d.pw",                // TLS 1.3 only, no ECH
            "cloudflareresearch.com",     // no ECH

            "enabled.tls13.com",          // no longer supports ECH
            "crypto.cloudflare.com",      // no longer supports ECH
    };
    private static String[] hostsEch = {
            "openstreetmap.org",          // now supports ECH
            "cloudflare-esni.com",        // now supports ECH

            // TEMP - commented out to avoid issues with unique formatting
            //"draft-13.esni.defo.ie:8413", // OpenSSL s_server
            //"draft-13.esni.defo.ie:8414", // OpenSSL s_server, likely forces HRR as it only likes P-384 for TLS =09
            // TEMP - causes prefetch exception "draft-13.esni.defo.ie:9413",
            //"draft-13.esni.defo.ie:10413", // nginx
            //"draft-13.esni.defo.ie:11413", // apache
            //"draft-13.esni.defo.ie:12413", // haproxy shared mode (haproxy terminates TLS)
            //"draft-13.esni.defo.ie:12414", // haproxy split mode (haproxy only decrypts ECH)
    };

    private static String[] hosts = new String[hostsNonEch.length + hostsEch.length];

    @BeforeClass
    public static void setUp() throws NoSuchAlgorithmException {
        System.out.println("========== SETUP BEGIN ===============================================================");
        Security.insertProviderAt(Conscrypt.newProvider(), 1);
        assertTrue(Conscrypt.isAvailable());
        assertTrue(Conscrypt.isConscrypt(SSLContext.getInstance("TLSv1.3")));
        System.arraycopy(hostsNonEch, 0, hosts, 0, hostsNonEch.length);
        System.arraycopy(hostsEch, 0, hosts, hostsNonEch.length, hostsEch.length);
        prefetchDns(hosts);
        System.out.println("========== SETUP END =================================================================");
    }

    @AfterClass
    public static void tearDown() throws NoSuchAlgorithmException {
        System.out.println("========== TEARDOWN BEGIN ============================================================");
        Security.removeProvider("Conscrypt");
        assertFalse(Conscrypt.isConscrypt(SSLContext.getInstance("TLSv1")));
        System.out.println("========== TEARDOWN END ==============================================================");
    }

    @Test
    public void testConnectSocket() throws IOException {
        boolean hostFailed = false;
        for (String h : hosts) {
            System.out.println(" = TEST CONNECT SOCKET FOR " + h);
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
                byte[] echConfigList = getEchConfigListFromDns(h);
                if (echConfigList != null) {
                    Conscrypt.setEchParameters(sslSocket, new EchParameters(true, echConfigList));
                    System.out.println("ENABLED ECH GREASE AND CONFIG LIST");
                    setUpEch = true;
                } else {
                    Conscrypt.setEchParameters(sslSocket, new EchParameters(true));
                    System.out.println("ENABLED ECH GREASE");
                }
            } catch (NamingException e) {
                System.out.println("GET CONFIG LIST THREW EXCEPTION FOR " + host);
                System.out.println(e.getMessage());
                hostFailed = true;
                continue;
            }
            sslSocket.setSoTimeout(TIMEOUT_MILLISECONDS);
            try {
                sslSocket.startHandshake();
                System.out.println("HANDSHAKE OK FOR " + host);
            } catch (Exception e) {
                System.out.println("HANDSHAKE THREW EXCEPTION FOR " + host);
                System.out.println(e.getMessage());
            }
            assertTrue(sslSocket.isConnected());
            AbstractConscryptSocket abstractConscryptSocket = (AbstractConscryptSocket) sslSocket;
            if (setUpEch) {
                assertTrue(abstractConscryptSocket.echAccepted());
            } else {
                assertFalse(abstractConscryptSocket.echAccepted());
            }
            sslSocket.close();
        }
        System.out.println("TEST FAILED FOR ONE OR MORE HOSTS: " + hostFailed);
        assertFalse(hostFailed);
    }

    @Rule
    public ExpectedException echRejectedExceptionRule = ExpectedException.none();

    @Test
    public void testEchConfigOnNonEchHosts() throws IOException {
        for (String h : hostsNonEch) {
            System.out.println(" = TEST ECH CONFIG ON NON ECH HOSTS FOR " + h);
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

            // load saved ech config with the expecation that the key mismatch will cause rejection
            byte[] echConfigList = TestUtils.readTestFile("draft-13.esni.defo.ie_12414-ech-config-list.bin");
            Conscrypt.setEchParameters(sslSocket, new EchParameters(echConfigList));

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
        boolean hostFailed = false;
        for (String host : hosts) {
            URL url = new URL("https://" + host);
            System.out.println(" = TEST CONNECT HTTPS URL CONNECTION FOR " + url);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            SSLSocketFactory delegateSocketFactory = connection.getSSLSocketFactory();
            assertTrue(Conscrypt.isConscrypt(delegateSocketFactory));
            try {
                byte[] echConfigList = getEchConfigListFromDns(host);
                if (echConfigList != null) {
                    connection.setSSLSocketFactory(new EchSSLSocketFactory(delegateSocketFactory, echConfigList));
                    System.out.println("CREATED SOCKET FACTORY WITH ECH GREASE AND CONFIG LIST");
                } else {
                    connection.setSSLSocketFactory(new EchSSLSocketFactory(delegateSocketFactory, true));
                    System.out.println("CREATED SOCKET FACTORY WITH ECH GREASE");
                }
            } catch (NamingException e) {
                System.out.println("GET CONFIG LIST THREW EXCEPTION FOR " + host);
                System.out.println(e.getMessage());
                hostFailed = true;
                continue;
            }
            // Cloudflare will return 403 Forbidden (error code 1010) unless a User Agent is set :-|
            connection.setRequestProperty("User-Agent", "Conscrypt EchInteropTest");
            connection.setConnectTimeout(0); // blocking connect with TCP timeout
            connection.setReadTimeout(0);

            int responseCode = -1;
            String contentType = "error";
            String cipherSuite = "error";
            try {
                responseCode = connection.getResponseCode();
                contentType = connection.getContentType().split(";")[0];
                cipherSuite = connection.getCipherSuite();
                System.out.println("GET CONNECTION INFO OK FOR " + url + " -> " + responseCode + " | " + contentType + " | " + cipherSuite);
            } catch (Exception e) {
                System.out.println("GET CONNECTION INFO THREW EXCEPTION FOR " + url);
                System.out.println(e.getMessage());
            }
            connection.getContent();
            assertEquals(200, responseCode);
            String[] options = {"text/html", "text/plain"};
            List<String> contentTypes = Arrays.asList(options);
            // some defo urls have different content types, is this an error?
            assertTrue(contentTypes.contains(contentType));
            assertTrue(cipherSuite.startsWith("TLS"));
            connection.disconnect();
        }
        System.out.println("TEST FAILED FOR ONE OR MORE HOSTS: " + hostFailed);
        assertFalse(hostFailed);
    }

    @Test
    public void testParseDnsAndConnect() throws IOException, NamingException {
        for (String h : hosts) {
            System.out.println(" = TEST PARSE DNS AND CONNECT FOR " + h);
            String[] hostPort = h.split(":");
            String host = hostPort[0];
            int port = 443;
            if (hostPort.length > 1) {
                port = Integer.parseInt(hostPort[1]);
            }

            byte[] echConfigList = null;
            try {
                echConfigList = getEchConfigListFromDns(h);
                System.out.println("ECH CONFIG LIST OK FOR " + h);
            } catch (Exception e) {
                System.out.println("ECH CONFIG LIST THREW EXCEPTION FOR " + h);
                System.out.println(e.getMessage());
            }

            if (echConfigList != null) {
                assertEquals("length should match inline declaration",
                        echConfigList[1] + 2,  // leading 0x00 and length bytes
                        echConfigList.length
                );
            } else {
                System.out.println("NO ECH CONFIG LIST FOUND IN DNS FOR " + h);
            }

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            assertTrue(Conscrypt.isConscrypt(sslSocketFactory));
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            assertTrue(Conscrypt.isConscrypt(sslSocket));
            if (echConfigList != null) {
                Conscrypt.setEchParameters(sslSocket, new EchParameters(true, echConfigList));
                System.out.println("ENABLED ECH GREASE AND CONFIG LIST");
            } else {
                Conscrypt.setEchParameters(sslSocket, new EchParameters(true));
                System.out.println("ENABLED ECH GREASE");
            }
            sslSocket.setSoTimeout(TIMEOUT_MILLISECONDS);
            sslSocket.startHandshake();
            assertTrue(sslSocket.isConnected());
            AbstractConscryptSocket abstractConscryptSocket = (AbstractConscryptSocket) sslSocket;
            System.out.println("ECHACCEPTED SET TO " + abstractConscryptSocket.echAccepted() + " FOR " + host);
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
            System.out.println(" = TEST PARSE DNS FROM FILES FOR " + hostString);
            String[] h = hostString.split(":");
            String host = h[0];
            if (h.length > 1) {
                if (!"443".equals(h[1])) {
                    host = "_" + h[1] + "._https." + h[0]; // query for non-standard port
                }
            }
            try {
                byte[] dnsAnswer = TestUtils.readTestFile(host + ".bin");
                echPbuf("DNS ANSWER", dnsAnswer);
                try {
                    DnsEchAnswer dnsEchAnswer = new DnsEchAnswer(dnsAnswer);
                    if (dnsEchAnswer.getEchConfigList() == null) {
                        System.out.println("ECH CONFIG LIST NULL FOR " + host);
                    } else {
                        echPbuf("ECH CONFIG LIST", dnsEchAnswer.getEchConfigList());
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
            // only parse HTTPS/65 (previous included SVCB/64, but why?)
            for (int i = 0; i < attr.size(); i++) {
                Object rr = attr.get(i);
                if (!(rr instanceof byte[])) {
                    continue;
                } else {
                    echConfigList = Conscrypt.getEchConfigListFromDnsRR((byte[]) rr);
                }
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
            Conscrypt.setEchParameters(sslSocket, new EchParameters(enableEchGrease, echConfigList));
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
    private static void prefetchDns(String[] hosts) {
        System.out.println("========== PREFETCH BEGIN ============================================================");
        for (final String host : hosts) {
            new Thread() {
                @Override
                public void run() {
                    String actualHost = host;
                    if (actualHost.contains(":")) {
                        // the reformatted host strings with ports for defo don't return ips
                        actualHost = actualHost.split(":")[0];
                    }
                    try {
                        InetAddress.getByName(actualHost);
                        getEchConfigListFromDns(host);
                        System.out.println("PREFETCH OK FOR " + actualHost);
                    } catch (NamingException e) {
                        System.out.println("PREFETCH FAILED FOR " + actualHost + ", GET ECH LIST THREW EXCEPTION");
                        System.out.println(e.getMessage());
                    } catch (UnknownHostException e) {
                        System.out.println("PREFETCH FAILED FOR " + actualHost + ", IP LOOKUP THREW EXCEPTION");
                        System.out.println(e.getMessage());
                    }
                }
            }.start();
        }
        System.out.println("========== PREFETCH END ==============================================================");
    }
}
