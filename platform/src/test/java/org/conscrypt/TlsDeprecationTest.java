/*
 * Copyright (C) 2024 The Android Open Source Project
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

import static org.conscrypt.TestUtils.isTlsV1Filtered;

import libcore.junit.util.SwitchTargetSdkVersionRule;
import libcore.junit.util.SwitchTargetSdkVersionRule.TargetSdkVersion;

import javax.net.ssl.SSLSocket;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.conscrypt.javax.net.ssl.TestSSLContext;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;

@RunWith(JUnit4.class)
public class TlsDeprecationTest {
    @TargetSdkVersion(35)
    @Test
    public void test_SSLSocket_SSLv3Unsupported_35() throws Exception {
        assumeFalse(isTlsV1Filtered());
        TestSSLContext context = TestSSLContext.create();
        final SSLSocket client =
                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSLv3"}));
        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSL"}));
    }

    @TargetSdkVersion(34)
    @Test
    public void test_SSLSocket_SSLv3Unsupported_34() throws Exception {
        TestSSLContext context = TestSSLContext.create();
        final SSLSocket client =
                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
        // For app compatibility, SSLv3 is stripped out when setting only.
        client.setEnabledProtocols(new String[] {"SSLv3"});
        assertEquals(0, client.getEnabledProtocols().length);
        try {
            client.setEnabledProtocols(new String[] {"SSL"});
            fail("SSLSocket should not support SSL protocol");
        } catch (IllegalArgumentException expected) {
            // Ignored.
        }
    }

    @TargetSdkVersion(34)
    @Test
    public void test_TLSv1Filtered_34() throws Exception {
        TestSSLContext context = TestSSLContext.create();
        final SSLSocket client =
                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
        client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"});
        assertEquals(1, client.getEnabledProtocols().length);
        assertEquals("TLSv1.2", client.getEnabledProtocols()[0]);
    }

    @TargetSdkVersion(35)
    @Test
    public void test_TLSv1Filtered_35() throws Exception {
        assumeFalse(isTlsV1Filtered());
        TestSSLContext context = TestSSLContext.create();
        final SSLSocket client =
                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
        assertThrows(IllegalArgumentException.class, () ->
            client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"}));
    }
}