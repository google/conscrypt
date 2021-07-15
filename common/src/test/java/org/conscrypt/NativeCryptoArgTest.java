/*
 * Copyright (C) 2020 The Android Open Source Project
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class NativeCryptoArgTest {
    // Null value passed in for a long which represents a native address
    private static final long NULL = 0L;
    /*
     * Non-null value passed in for a long which represents a native address. Shouldn't
     * ever get de-referenced but we make it a multiple of 4 to avoid any alignment errors.
     * Used in the case where there are multiple checks we want to test in a native method,
     * so we can get past the first check and test the second one.
     */
    private static final long NOT_NULL = 4L;
    private static final String CONSCRYPT_PACKAGE = NativeCryptoArgTest.class.getCanonicalName()
            .substring(0, NativeCryptoArgTest.class.getCanonicalName().lastIndexOf('.') + 1);
    private static final Set<String> testedMethods = new HashSet<>();
    private final Map<String, Class<?>> classCache = new HashMap<>();
    private final Map<String, Method> methodMap = buildMethodMap();

    @AfterClass
    public static void after() {
        // TODO(prb): Temporary hacky check - remove
        assertTrue(testedMethods.size() >= 190);
    }

    @Test
    public void ecMethods() throws Throwable {
        String[] illegalArgMethods = new String[] {
                "EC_GROUP_new_arbitrary"
        };
        String[] ioExMethods = new String[] {
                "EC_KEY_parse_curve_name",
                "EC_KEY_marshal_curve_name"
        };

        // All of the EC_* methods apart from the exceptions below throw NPE if their
        // first argument is null.
        MethodFilter filter = MethodFilter.newBuilder("EC_ methods")
                .hasPrefix("EC_")
                .except(illegalArgMethods)
                .except(ioExMethods)
                .expectSize(16)
                .build();
        testMethods(filter, NullPointerException.class);

        filter = MethodFilter.nameFilter("EC_ methods (IllegalArgument)", illegalArgMethods);
        testMethods(filter, IllegalArgumentException.class);

        filter = MethodFilter.nameFilter("EC_ methods (IOException)", ioExMethods);
        testMethods(filter, IOException.class);
    }

    @Test
    public void macMethods() throws Throwable {
        // All of the non-void HMAC and CMAC methods throw NPE when passed a null pointer
        MethodFilter filter = MethodFilter.newBuilder("HMAC methods")
                .hasPrefix("HMAC_")
                .takesArguments()
                .expectSize(5)
                .build();
        testMethods(filter, NullPointerException.class);

        filter = MethodFilter.newBuilder("CMAC methods")
                .hasPrefix("CMAC_")
                .takesArguments()
                .expectSize(5)
                .build();
        testMethods(filter, NullPointerException.class);
    }

    @Test
    public void sslMethods() throws Throwable {
        // These methods don't throw on a null first arg as they can get called before the
        // connection is fully initialised. However if the first arg is non-NULL, any subsequent
        // null args should throw NPE.
        String[] nonThrowingMethods = new String[] {
                "SSL_interrupt",
                "SSL_shutdown",
                "ENGINE_SSL_shutdown",
        };

        // Most of the NativeSsl methods take a long holding a pointer to the native
        // object followed by a {@code NativeSsl} holder object. However the second arg
        // is unused(!) so we don't need to test it.
        MethodFilter filter = MethodFilter.newBuilder("NativeSsl methods")
                .hasArg(0, long.class)
                .hasArg(1, conscryptClass("NativeSsl"))
                .except(nonThrowingMethods)
                .expectSize(60)
                .build();

        testMethods(filter, NullPointerException.class);

        // Many of the SSL_* methods take a single long which points
        // to a native object.
        filter = MethodFilter.newBuilder("1-arg SSL methods")
                .hasPrefix("SSL_")
                .hasArgLength(1)
                .hasArg(0, long.class)
                .expectSize(10)
                .build();

        testMethods(filter, NullPointerException.class);

        filter = MethodFilter.nameFilter("Non throwing NativeSsl methods", nonThrowingMethods);
        testMethods(filter, null);

        expectVoid("SSL_shutdown", NOT_NULL, null, null, null);
        expectNPE("SSL_shutdown", NOT_NULL, null, new FileDescriptor(), null);
        expectNPE("ENGINE_SSL_shutdown", NOT_NULL, null, null);
        expectVoid("SSL_set_session", NOT_NULL, null, NULL);
    }

    @Test
    public void evpMethods() throws Throwable {
        String[] illegalArgMethods = new String[] {
                "EVP_AEAD_CTX_open_buf",
                "EVP_AEAD_CTX_seal_buf",
                "EVP_PKEY_new_RSA"
        };
        String[] nonThrowingMethods = new String[] {
                "EVP_MD_CTX_destroy",
                "EVP_PKEY_CTX_free",
                "EVP_PKEY_free",
                "EVP_CIPHER_CTX_free"
        };

        // All of the non-void EVP_ methods apart from the above should throw on a null
        // first argument.
        MethodFilter filter = MethodFilter.newBuilder("EVP methods")
                .hasPrefix("EVP_")
                .takesArguments()
                .except(illegalArgMethods)
                .except(nonThrowingMethods)
                .expectSize(45)
                .build();

        testMethods(filter, NullPointerException.class);

        filter = MethodFilter.nameFilter("EVP methods (IllegalArgument)", illegalArgMethods);
        testMethods(filter, IllegalArgumentException.class);

        filter = MethodFilter.nameFilter("EVP methods (non-throwing)", nonThrowingMethods);
        testMethods(filter, null);
    }

    @Test
    public void x509Methods() throws Throwable {
        // A number of X509 methods have a native pointer as arg 0 and an
        // OpenSSLX509Certificate or OpenSSLX509CRL as arg 1.
        MethodFilter filter = MethodFilter.newBuilder("X509 methods")
                .hasArgLength(2)
                .hasArg(0, long.class)
                .hasArg(1, conscryptClass("OpenSSLX509Certificate"),
                        conscryptClass("OpenSSLX509CRL"))
                .expectSize(32)
                .build();
        // TODO(prb): test null second argument
        testMethods(filter, NullPointerException.class);

        // The rest of the X509 methods are somewhat ad hoc.
        expectNPE("d2i_X509", (Object) null);

        invokeAndExpect( conscryptThrowable("OpenSSLX509CertificateFactory$ParsingException"),
                 "d2i_X509", new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0});

        expectNPE("d2i_X509_bio", NULL);
        expectNPE("PEM_read_bio_X509", NULL);
        expectNPE("ASN1_seq_pack_X509", (Object) null);

        // TODO(prb): Check what this should really throw
        // expectNPE("ASN1_seq_pack_X509", (Object) new long[] { NULL });

        expectNPE("ASN1_seq_unpack_X509_bio", NULL);

        //
        expectNPE("X509_cmp", NULL, null, NULL, null);
        expectNPE("X509_cmp", NOT_NULL, null, NULL, null);
        expectNPE("X509_cmp", NULL, null, NOT_NULL, null);

        expectNPE("X509_print_ex", NULL, NULL, null, NULL, NULL);
        expectNPE("X509_print_ex", NOT_NULL, NULL, null, NULL, NULL);
        expectNPE("X509_print_ex", NULL, NOT_NULL, null, NULL, NULL);
    }

    private void testMethods(MethodFilter filter, Class<? extends Throwable> exceptionClass)
            throws Throwable {
        List<Method> methods = filter.filter(methodMap.values());

        for (Method method : methods) {
            List<Object[]> argsLists = permuteArgs(method);
            for (Object[] args : argsLists) {
                invokeAndExpect(exceptionClass, method, args);
            }
        }
    }

    private List<Object[]> permuteArgs(Method method) {
        // For now just supply 0 for integral types and null for everything else
        // TODO: allow user defined strategy, e.g. if two longs passed as native refs,
        // generate {NULL,NULL}, {NULL,NOT_NULL}, {NOT_NULL,NULL} to test both null checks
        List<Object[]> result = new ArrayList<>(1);

        Class<?>[] argTypes = method.getParameterTypes();

        int argCount = argTypes.length;
        assertTrue(argCount > 0);
        Object[] args = new Object[argCount];

        for (int arg = 0; arg < argCount; arg++) {
            if (argTypes[arg] == int.class) {
                args[arg] = 0;
            } else if (argTypes[arg] == long.class) {
                args[arg] = NULL;
            } else if (argTypes[arg] == boolean.class) {
                args[arg] = false;
            } else {
                args[arg] = null;
            }
        }
        result.add(args);
        return result;
    }

    private void expectVoid(String methodName, Object... args) throws Throwable {
        invokeAndExpect(null, methodName, args);
    }

    private void expectNPE(String methodName, Object... args) throws Throwable {
        invokeAndExpect(NullPointerException.class, methodName, args);
    }

    private void invokeAndExpect(Class<? extends Throwable> expectedThrowable, String methodName,
                                   Object... args) throws Throwable {
        Method method = methodMap.get(methodName);
        assertNotNull(method);
        assertEquals(methodName, method.getName());
        invokeAndExpect(expectedThrowable, method, args);
    }

    private void invokeAndExpect(Class<? extends Throwable> expectedThrowable, Method method,
                                   Object... args) throws Throwable {
        try {
            method.invoke(null, args);
            if (expectedThrowable != null) {
                fail("No exception thrown by method " + method.getName());
            }
        } catch (IllegalAccessException e) {
            throw new AssertionError("Illegal access", e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (expectedThrowable != null) {
                assertEquals("Method: " + method.getName(), expectedThrowable, cause.getClass());
            } else {
                throw cause;
            }
        }
        testedMethods.add(method.getName());
    }

    @SuppressWarnings("unchecked")
    private Class<? extends Throwable> conscryptThrowable(String name) {
        Class<?> klass = conscryptClass(name);
        assertNotNull(klass);
        assertTrue(Throwable.class.isAssignableFrom(klass));
        return (Class<? extends Throwable>) klass;
    }

    private Class<?> conscryptClass(String className) {
        return classCache.computeIfAbsent(className, s -> {
            try {
                return Class.forName(CONSCRYPT_PACKAGE + className);
            } catch (ClassNotFoundException e) {
                return null;
            }
        });
    }

    private Map<String, Method> buildMethodMap() {
        Map<String, Method> classMap = new HashMap<>();
        assertNotNull(classMap);
        Class<?> nativeCryptoClass = conscryptClass("NativeCrypto");
        assertNotNull(nativeCryptoClass);
        for (Method method : nativeCryptoClass.getDeclaredMethods()) {
            int modifiers = method.getModifiers();
            if (!Modifier.isNative(modifiers)) {
                continue;
            }
            method.setAccessible(true);
            classMap.put(method.getName(), method);
        }
        return classMap;
    }
}
