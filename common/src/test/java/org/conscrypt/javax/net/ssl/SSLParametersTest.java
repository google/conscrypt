/*
 * Copyright (C) 2010 The Android Open Source Project
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

package org.conscrypt.javax.net.ssl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLParameters;
import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SSLParametersTest {
    @Test
    public void test_SSLParameters_emptyConstructor() {
        SSLParameters p = new SSLParameters();
        assertNull(p.getCipherSuites());
        assertNull(p.getProtocols());
        assertFalse(p.getWantClientAuth());
        assertFalse(p.getNeedClientAuth());
    }

    @Test
    public void test_SSLParameters_cipherSuitesConstructor() {
        String[] cipherSuites = new String[] {"foo", null, "bar"};
        SSLParameters p = new SSLParameters(cipherSuites);
        assertNotNull(p.getCipherSuites());
        assertNotSame(cipherSuites, p.getCipherSuites());
        assertEquals(Arrays.asList(cipherSuites), Arrays.asList(p.getCipherSuites()));
        assertNull(p.getProtocols());
        assertFalse(p.getWantClientAuth());
        assertFalse(p.getNeedClientAuth());
    }

    @Test
    public void test_SSLParameters_cpherSuitesProtocolsConstructor() {
        String[] cipherSuites = new String[] {"foo", null, "bar"};
        String[] protocols = new String[] {"baz", null, "qux"};
        SSLParameters p = new SSLParameters(cipherSuites, protocols);
        assertNotNull(p.getCipherSuites());
        assertNotNull(p.getProtocols());
        assertNotSame(cipherSuites, p.getCipherSuites());
        assertNotSame(protocols, p.getProtocols());
        assertEquals(Arrays.asList(cipherSuites), Arrays.asList(p.getCipherSuites()));
        assertEquals(Arrays.asList(protocols), Arrays.asList(p.getProtocols()));
        assertFalse(p.getWantClientAuth());
        assertFalse(p.getNeedClientAuth());
    }

    @Test
    public void test_SSLParameters_CipherSuites() {
        SSLParameters p = new SSLParameters();
        assertNull(p.getCipherSuites());

        // confirm clone on input
        String[] cipherSuites = new String[] {"fnord"};
        String[] copy = cipherSuites.clone();
        p.setCipherSuites(copy);
        copy[0] = null;
        assertEquals(Arrays.asList(cipherSuites), Arrays.asList(p.getCipherSuites()));

        // confirm clone on output
        assertNotSame(p.getCipherSuites(), p.getCipherSuites());
    }

    @Test
    public void test_SSLParameters_Protocols() {
        SSLParameters p = new SSLParameters();
        assertNull(p.getProtocols());

        // confirm clone on input
        String[] protocols = new String[] {"fnord"};
        String[] copy = protocols.clone();
        p.setProtocols(copy);
        copy[0] = null;
        assertEquals(Arrays.asList(protocols), Arrays.asList(p.getProtocols()));

        // confirm clone on output
        assertNotSame(p.getProtocols(), p.getProtocols());
    }

    @Test
    public void test_SSLParameters_ClientAuth() {
        SSLParameters p = new SSLParameters();
        assertFalse(p.getWantClientAuth());
        assertFalse(p.getNeedClientAuth());

        // confirm turning one on by itself
        p.setWantClientAuth(true);
        assertTrue(p.getWantClientAuth());
        assertFalse(p.getNeedClientAuth());

        // confirm turning setting on toggles the other
        p.setNeedClientAuth(true);
        assertFalse(p.getWantClientAuth());
        assertTrue(p.getNeedClientAuth());

        // confirm toggling back
        p.setWantClientAuth(true);
        assertTrue(p.getWantClientAuth());
        assertFalse(p.getNeedClientAuth());
    }

    @Test
    public void test_SSLParameters_setServerNames_duplicatedNameThrows() throws Exception {
        TestUtils.assumeSNIHostnameAvailable();

        SSLParameters p = new SSLParameters();
        ArrayList<SNIServerName> dupeNames = new ArrayList<SNIServerName>();
        dupeNames.add(new SNIHostName("www.example.com"));
        dupeNames.add(new SNIHostName("www.example.com"));
        try {
            p.setServerNames(dupeNames);
            fail("Should throw IllegalArgumentException when names are duplicated");
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
    }

    @Test
    public void test_SSLParameters_setServerNames_setNull_getNull() throws Exception {
        TestUtils.assumeSNIHostnameAvailable();
        SSLParameters p = new SSLParameters();
        p.setServerNames(
                Collections.singletonList((SNIServerName) new SNIHostName("www.example.com")));
        assertNotNull(p.getServerNames());
        p.setServerNames(null);
        assertNull(p.getServerNames());
    }

    @Test
    public void test_SSLParameters_setServerNames_setEmpty_getEmpty() throws Exception {
        TestUtils.assumeSNIHostnameAvailable();
        SSLParameters p = new SSLParameters();
        p.setServerNames(new ArrayList<SNIServerName>());
        Collection<SNIServerName> actual = p.getServerNames();
        assertNotNull(actual);
        assertEquals(0, actual.size());
    }

    @Test
    public void test_SSLParameters_getServerNames_unmodifiable() throws Exception {
        TestUtils.assumeSNIHostnameAvailable();
        SSLParameters p = new SSLParameters();
        p.setServerNames(
                Collections.singletonList((SNIServerName) new SNIHostName("www.example.com")));
        Collection<SNIServerName> actual = p.getServerNames();
        try {
            actual.add(new SNIHostName("www.foo.com"));
            fail("Should not allow modifications to the list");
        } catch (UnsupportedOperationException expected) {
            // Ignored.
        }
    }

    @Test
    public void test_SSLParameters_setSNIMatchers_duplicatedNameThrows() throws Exception {
        TestUtils.assumeSNIHostnameAvailable();
        SSLParameters p = new SSLParameters();
        ArrayList<SNIMatcher> dupeMatchers = new ArrayList<SNIMatcher>();
        dupeMatchers.add(SNIHostName.createSNIMatcher("www\\.example\\.com"));
        dupeMatchers.add(SNIHostName.createSNIMatcher("www\\.example\\.com"));
        try {
            p.setSNIMatchers(dupeMatchers);
            fail("Should throw IllegalArgumentException when matchers are duplicated");
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
    }

    @Test
    public void test_SSLParameters_setSNIMatchers_setNull_getNull() throws Exception {
        TestUtils.assumeSNIHostnameAvailable();
        SSLParameters p = new SSLParameters();
        p.setSNIMatchers(
                Collections.singletonList(SNIHostName.createSNIMatcher("www\\.example\\.com")));
        assertNotNull(p.getSNIMatchers());
        p.setSNIMatchers(null);
        assertNull(p.getSNIMatchers());
    }

    @Test
    public void test_SSLParameters_setSNIMatchers_setEmpty_getEmpty() throws Exception {
        TestUtils.assumeSNIHostnameAvailable();
        SSLParameters p = new SSLParameters();
        p.setSNIMatchers(
                Collections.singletonList(SNIHostName.createSNIMatcher("www\\.example\\.com")));
        assertEquals(1, p.getSNIMatchers().size());
        p.setSNIMatchers(Collections.<SNIMatcher>emptyList());
        Collection<SNIMatcher> actual = p.getSNIMatchers();
        assertNotNull(actual);
        assertEquals(0, actual.size());
    }

    @Test
    public void test_SSLParameters_getSNIMatchers_unmodifiable() throws Exception {
        TestUtils.assumeSNIHostnameAvailable();
        SSLParameters p = new SSLParameters();
        p.setSNIMatchers(
                Collections.singletonList(SNIHostName.createSNIMatcher("www\\.example\\.com")));
        Collection<SNIMatcher> actual = p.getSNIMatchers();
        try {
            actual.add(SNIHostName.createSNIMatcher("www\\.google\\.com"));
            fail("Should not allow modification of list");
        } catch (UnsupportedOperationException expected) {
            // Ignored.
        }
    }
}
