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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.KeyStoreBuilderParameters;
import org.conscrypt.java.security.TestKeyStore;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class KeyStoreBuilderParametersTest {

    private static void assumeObjectsAvailable() {
        boolean available = false;
        try {
            Class.forName("java.util.Objects");
            available = true;
        } catch (ClassNotFoundException ignore) {
            // Ignored
        }
        Assume.assumeTrue("Skipping test: Objects unavailable", available);
    }

    @Test
    public void test_init_Builder_null() {
        // KeyStoreBuilderParameters' constructor didn't check for null until
        // Objects.requireNonNull was added
        assumeObjectsAvailable();
        try {
            new KeyStoreBuilderParameters((KeyStore.Builder) null);
            fail();
        } catch (NullPointerException expected) {
        }
    }

    @Test
    public void test_init_Builder() {
        TestKeyStore testKeyStore = TestKeyStore.getClient();
        KeyStore.Builder builder = KeyStore.Builder.newInstance(
                testKeyStore.keyStore, new PasswordProtection(testKeyStore.storePassword));
        KeyStoreBuilderParameters ksbp = new KeyStoreBuilderParameters(builder);
        assertNotNull(ksbp);
        assertNotNull(ksbp.getParameters());
        assertEquals(1, ksbp.getParameters().size());
        assertSame(builder, ksbp.getParameters().get(0));
    }

    @Test
    public void test_init_List_null() {
        try {
            new KeyStoreBuilderParameters((List<KeyStore.Builder>) null);
            fail();
        } catch (NullPointerException expected) {
            // Ignored.
        }
    }

    @Test
    public void test_init_List() {
        TestKeyStore testKeyStore1 = TestKeyStore.getClient();
        TestKeyStore testKeyStore2 = TestKeyStore.getServer();
        KeyStore.Builder builder1 = KeyStore.Builder.newInstance(
                testKeyStore1.keyStore, new PasswordProtection(testKeyStore1.storePassword));
        KeyStore.Builder builder2 = KeyStore.Builder.newInstance(
                testKeyStore2.keyStore, new PasswordProtection(testKeyStore2.storePassword));

        List<KeyStore.Builder> list = Arrays.asList(builder1, builder2);
        KeyStoreBuilderParameters ksbp = new KeyStoreBuilderParameters(list);
        assertNotNull(ksbp);
        assertNotNull(ksbp.getParameters());
        assertNotSame(list, ksbp.getParameters());
        assertEquals(2, ksbp.getParameters().size());
        assertSame(builder1, ksbp.getParameters().get(0));
        assertSame(builder2, ksbp.getParameters().get(1));

        // confirm result is not modifiable
        try {
            ksbp.getParameters().set(0, builder2);
            fail();
        } catch (UnsupportedOperationException expected) {
            // Ignored.
        }

        // confirm result is a copy of original
        list.set(0, builder2);
        assertSame(builder1, ksbp.getParameters().get(0));
    }
}
