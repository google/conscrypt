/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.harmony.crypto.tests.javax.crypto;

import dalvik.annotation.TestTargetClass;
import dalvik.annotation.TestInfo;
import dalvik.annotation.TestLevel;
import dalvik.annotation.TestTarget;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.Provider;

import javax.crypto.ExemptionMechanism;
import javax.crypto.ExemptionMechanismSpi;

import org.apache.harmony.crypto.tests.support.MyExemptionMechanismSpi;
import org.apache.harmony.crypto.tests.support.MyExemptionMechanismSpi.tmpKey;
import org.apache.harmony.security.tests.support.SpiEngUtils;

import junit.framework.TestCase;

@TestTargetClass(ExemptionMechanism.class)
/**
 * Tests for <code>ExemptionMechanism</code> class constructors and methods
 * 
 */

public class ExemptionMechanismTest extends TestCase {

    private static final String srvExemptionMechanism = "ExemptionMechanism";

    private static final String defaultAlg = "EMech";

    private static final String ExemptionMechanismProviderClass = "org.apache.harmony.crypto.tests.support.MyExemptionMechanismSpi";

    /**
     * Test for <code>ExemptionMechanism</code> constructor 
     * Assertion: creates new object using provider and mechanism name
     */
@TestInfo(
      level = TestLevel.COMPLETE,
      purpose = "",
      targets = {
        @TestTarget(
          methodName = "ExemptionMechanism",
          methodArgs = {javax.crypto.ExemptionMechanismSpi.class, java.security.Provider.class, java.lang.String.class}
        )
    })
    public void testExemptionMechanism() throws Exception {
        Provider mProv = (new SpiEngUtils()).new MyProvider("MyExMechProvider",
                "Provider for ExemptionMechanism testing",
                srvExemptionMechanism.concat(".").concat(defaultAlg),
                ExemptionMechanismProviderClass);

        ExemptionMechanismSpi spi = new MyExemptionMechanismSpi();

        ExemptionMechanism em = new ExemptionMechanism(spi, mProv, defaultAlg) {};
        assertEquals("Incorrect provider", em.getProvider(), mProv);
        assertEquals("Incorrect algorithm", em.getName(), defaultAlg);
        try {
            em.init(null);
            fail("InvalidKeyException must be thrown");
        } catch (InvalidKeyException e) {}

        try {
            em.getOutputSize(100);
            fail("IllegalStateException must be thrown");
        } catch (IllegalStateException e) {}


        em = new ExemptionMechanism(null, null, null) {};
        assertNull("Incorrect mechanism", em.getName());
        assertNull("Incorrect provider", em.getProvider());
        try {
            em.init(null);
            fail("NullPointerException must be thrown");
        } catch (NullPointerException e) {}
        try {
            em.getOutputSize(100);
            fail("IllegalStateException must be thrown");
        } catch (IllegalStateException e) {}
    }

    /**
     * @tests javax/crypto/ExemptionMechanism#getInstance(String algorithm, String provider)
     * Checks exception order
     */
@TestInfo(
      level = TestLevel.PARTIAL,
      purpose = "Regression test.",
      targets = {
        @TestTarget(
          methodName = "getInstance",
          methodArgs = {java.lang.String.class, java.lang.String.class}
        )
    })
    public void testGetInstance() throws Exception {
        //Regression for HARMONY-762
        try {
            ExemptionMechanism.getInstance((String) null, "aaa");
            fail("NoSuchProviderException must be thrown");
        } catch (NoSuchProviderException pe) {
            //expected
        }
    }
    
    /**
     * Test for <code>isCryptoAllowed(Key key)</code> method 
     */
@TestInfo(
      level = TestLevel.PARTIAL,
      purpose = "Regression test.",
      targets = {
        @TestTarget(
          methodName = "isCryptoAllowed",
          methodArgs = {java.security.Key.class}
        )
    })
    public void testIsCryptoAllowed() throws Exception {

        //Regression for HARMONY-1029
        Provider mProv = (new SpiEngUtils()).new MyProvider("MyExMechProvider",
                "Provider for ExemptionMechanism testing",
                srvExemptionMechanism.concat(".").concat(defaultAlg),
                ExemptionMechanismProviderClass);

        ExemptionMechanism em = new ExemptionMechanism(
                new MyExemptionMechanismSpi(), mProv, defaultAlg) {
        };

        Key key = new MyExemptionMechanismSpi().new tmpKey("Proba", new byte[0]);

        assertFalse(em.isCryptoAllowed(key));

        em.init(key);
        assertFalse(em.isCryptoAllowed(key));

        em.genExemptionBlob();
        assertTrue(em.isCryptoAllowed(key));

        Key key1 = new MyExemptionMechanismSpi().new tmpKey("Proba",
                new byte[] { 1 });
        assertFalse(em.isCryptoAllowed(key1));

        em.init(key1);
        assertFalse(em.isCryptoAllowed(key));
    }
    
    /**
     * Test for <code>genExemptionBlob((byte[] output, int outputOffset)</code> method
     */
@TestInfo(
      level = TestLevel.PARTIAL,
      purpose = "Regression test",
      targets = {
        @TestTarget(
          methodName = "genExemptionBlob",
          methodArgs = {byte[].class, int.class}
        )
    })
    public void testGenExemptionBlob() throws Exception {

        //Regression for HARMONY-1029
        Provider mProv = (new SpiEngUtils()).new MyProvider("MyExMechProvider",
                "Provider for ExemptionMechanism testing",
                srvExemptionMechanism.concat(".").concat(defaultAlg),
                ExemptionMechanismProviderClass);

        ExemptionMechanism em = new ExemptionMechanism(
                new MyExemptionMechanismSpi(), mProv, defaultAlg) {
        };

        Key key = new MyExemptionMechanismSpi().new tmpKey("Proba", new byte[0]);

        em.init(key);
        // ExemptionMechanism doesn't check parameters
        // it is a responsibility of ExemptionMechanismSpi
        em.genExemptionBlob(null, 0);
        em.genExemptionBlob(new byte[0], 0);
        em.genExemptionBlob(new byte[10], -5);

    }

}
