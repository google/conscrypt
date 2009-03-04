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

/**
* @author Boris V. Kuznetsov
* @version $Revision$
*/

package org.apache.harmony.crypto.tests.javax.crypto;

import dalvik.annotation.TestTargetClass;
import dalvik.annotation.TestTargets;
import dalvik.annotation.TestLevel;
import dalvik.annotation.TestTargetNew;

import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NullCipher;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

@TestTargetClass(NullCipher.class)
/**
 *
 * Tests for NullCipher
 */
public class NullCipherTest extends TestCase {

    private Cipher c;
    
    protected void setUp() throws Exception {
        super.setUp();
        c = new NullCipher();
    }

    @TestTargets({
        @TestTargetNew(
            level = TestLevel.COMPLETE,
            notes = "Class checks inherited methods.",
            method = "getAlgorithm",
            args = {}
        ),
        @TestTargetNew(
            level = TestLevel.COMPLETE,
            notes = "Class checks inherited methods.",
            method = "NullCipher",
            args = {}
        )
    })
    public void testGetAlgorithm() {
        c.getAlgorithm();
    }

    @TestTargetNew(
        level = TestLevel.COMPLETE,
        notes = "Checks inherited method from Cipher.",
        method = "getBlockSize",
        args = {}
    )
    public void testGetBlockSize() {
        assertEquals("Incorrect BlockSize", 1, c.getBlockSize());
    }

    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "IllegalStateException checking missed. Checks inherited method from Cipher.",
        method = "getOutputSize",
        args = {int.class}
    )
    public void testGetOutputSize() {
        assertEquals("Incorrect OutputSize", 111, c.getOutputSize(111));
    }

    @TestTargets({
        @TestTargetNew(
            level = TestLevel.COMPLETE,
            notes = "Checks inherited method from Cipher.",
            method = "getIV",
            args = {}
        ),
        @TestTargetNew(
                level = TestLevel.COMPLETE,
                notes = "Checks inherited method from Cipher.",
                clazz = CipherSpi.class,
                method = "engineGetIV",
                args = {}
        )
    })
    public void testGetIV() {
        assertTrue("Incorrect IV", Arrays.equals(c.getIV(), new byte[8]));
    }

    @TestTargetNew(
        level = TestLevel.COMPLETE,
        notes = "Checks inherited method from Cipher.",
        method = "getParameters",
        args = {}
    )
    public void testGetParameters() {
        assertNull("Incorrect Parameters", c.getParameters());
    }

    @TestTargetNew(
        level = TestLevel.COMPLETE,
        notes = "Checks inherited method from Cipher.",
        method = "getExemptionMechanism",
        args = {}
    )
    public void testGetExemptionMechanism() {
        assertNull("Incorrect ExemptionMechanism", c.getExemptionMechanism());
    }

    /*
     * Class under test for void init(int, Key)
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "InvalidKeyException checking missed. Checks inherited method from Cipher.",
        method = "init",
        args = {int.class, java.security.Key.class}
    )
    public void testInitintKey() throws Exception {
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[1], "algorithm"));
    
    }

    /*
     * Class under test for void init(int, Key, SecureRandom)
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "InvalidKeyException checking missed. Checks inherited method from Cipher.",
        method = "init",
        args = {int.class, java.security.Key.class, java.security.SecureRandom.class}
    )
    public void testInitintKeySecureRandom() throws Exception {
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[1],
                "algorithm"), new SecureRandom());
    }

    /*
     * Class under test for void init(int, Key, AlgorithmParameterSpec)
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "init",
        args = {int.class, java.security.Key.class, java.security.spec.AlgorithmParameterSpec.class}
    )
    public void testInitintKeyAlgorithmParameterSpec() throws Exception {
        class myAlgorithmParameterSpec implements java.security.spec.AlgorithmParameterSpec {}
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[1],
                "algorithm"), new myAlgorithmParameterSpec());
    }

    /*
     * Class under test for byte[] update(byte[])
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL_COMPLETE,
        notes = "IllegalStateException checking missed. Checks inherited method from Cipher.",
        method = "update",
        args = {byte[].class}
    )
    public void testUpdatebyteArray() throws Exception {
        byte [] b = {1, 2, 3, 4, 5};
        byte [] r = c.update(b);
        assertEquals("different length", b.length, r.length);
        assertTrue("different content", Arrays.equals(b, r));
    }

    /*
     * Class under test for byte[] update(byte[], int, int)
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "IllegalStateException checking missed. Checks inherited method from Cipher.",
        method = "update",
        args = {byte[].class, int.class, int.class}
    )
    public void testUpdatebyteArrayintint() throws Exception {
        byte [] b = {1, 2, 3, 4, 5};
        byte [] r = c.update(b, 0, 5);
        assertEquals("different length", b.length, r.length);
        assertTrue("different content", Arrays.equals(b, r));
        
        r = c.update(b, 1, 3);
        assertEquals("different length", 3, r.length);
        for (int i = 0; i < 3; i++) {
            assertEquals("different content", b[i + 1], r[i]);
        }
    }

    /*
     * Class under test for int update(byte[], int, int, byte[])
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "update",
        args = {byte[].class, int.class, int.class, byte[].class}
    )
    public void testUpdatebyteArrayintintbyteArray() throws Exception {
        byte [] b = {1, 2, 3, 4, 5};
        byte [] r = new byte[5]; 
        c.update(b, 0, 5, r);            
        assertTrue("different content", Arrays.equals(b, r));        
    }

    /*
     * Class under test for int update(byte[], int, int, byte[], int)
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "update",
        args = {byte[].class, int.class, int.class, byte[].class, int.class}
    )
    public void testUpdatebyteArrayintintbyteArrayint() throws Exception {
        byte [] b = {1, 2, 3, 4, 5};
        byte [] r = new byte[5]; 
        c.update(b, 0, 5, r, 0);            
        assertTrue("different content", Arrays.equals(b, r));
    }

    /*
     * Class under test for byte[] doFinal()
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "doFinal",
        args = {}
    )
    public void testDoFinal() throws Exception {
        assertNull("doFinal failed", c.doFinal());
    }

    /*
     * Class under test for int doFinal(byte[], int)
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "doFinal",
        args = {byte[].class, int.class}
    )
    public void testDoFinalbyteArrayint() throws Exception {
        byte [] r = new byte[5];
        assertEquals("doFinal failed", 0, c.doFinal(r, 0));
    }

    /*
     * Class under test for byte[] doFinal(byte[])
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "doFinal",
        args = {byte[].class}
    )
    public void testDoFinalbyteArray() throws Exception {
        byte [] b = {1, 2, 3, 4, 5};
        byte [] r = null; 
        r = c.doFinal(b);
        assertEquals("different length", b.length, r.length);
        assertTrue("different content", Arrays.equals(b, r));        
    }

    /*
     * Class under test for byte[] doFinal(byte[], int, int)
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "doFinal",
        args = {byte[].class, int.class, int.class}
    )
    public void testDoFinalbyteArrayintint() throws Exception {
        byte [] b = {1, 2, 3, 4, 5};
        byte [] r = null;
        r = c.doFinal(b, 0, 5);
        assertEquals("different length", b.length, r.length);
        assertTrue("different content", Arrays.equals(b, r));
        
        r = c.doFinal(b, 1, 3);
        assertEquals("different length", 3, r.length);
        for (int i = 0; i < 3; i++) {
            assertEquals("different content", b[i + 1], r[i]);
        }
    }

    /*
     * Class under test for byte[] update(byte[], int, int)
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "update",
        args = {byte[].class, int.class, int.class}
    )
    public void testUpdatebyteArrayintint2() {
        //Regression for HARMONY-758
        try {
            new NullCipher().update(new byte[1], 1, Integer.MAX_VALUE);
            fail("Expected IllegalArgumentException was not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    /*
     * Class under test for int doFinal(byte[], int, int, byte[])
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "doFinal",
        args = {byte[].class, int.class, int.class, byte[].class}
    )
    public void testDoFinalbyteArrayintintbyteArray() throws Exception {
        byte [] b = {1, 2, 3, 4, 5};
        byte [] r = new byte[5]; 
        c.doFinal(b, 0, 5, r);            
        assertTrue("different content", Arrays.equals(b, r));
    }

    /*
     * Class under test for int doFinal(byte[], int, int, byte[])
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "doFinal",
        args = {byte[].class, int.class, int.class, byte[].class}
    )
    public void testDoFinalbyteArrayintintbyteArray2() throws Exception {
        //Regression for HARMONY-758
        try {
            new NullCipher().update(new byte[1], 1, Integer.MAX_VALUE, 
                    new byte[1]);
            fail("Expected IllegalArgumentException was not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    /*
     * Class under test for int doFinal(byte[], int, int, byte[])
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "doFinal",
        args = {byte[].class, int.class, int.class, byte[].class}
    )
    public void testDoFinalbyteArrayintintbyteArray3() throws Exception {
        //Regression for HARMONY-758
        try {
            new NullCipher().update(new byte[1], 0, 1, new byte[0]);
            fail("Expected IndexOutOfBoundsException was not thrown");
        } catch (IndexOutOfBoundsException e) {
        }
    }

    /*
     * Class under test for int doFinal(byte[], int, int, byte[], int)
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "doFinal",
        args = {byte[].class, int.class, int.class, byte[].class, int.class}
    )
    public void testDoFinalbyteArrayintintbyteArrayint() throws Exception {
        byte [] b = {1, 2, 3, 4, 5};
        byte [] r = new byte[5]; 
        c.doFinal(b, 0, 5, r, 0);
        assertTrue("different content", Arrays.equals(b, r));
    }

    /*
     * Class under test for int doFinal(byte[], int, int, byte[], int)
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "doFinal",
        args = {byte[].class, int.class, int.class, byte[].class, int.class}
    )
    public void testDoFinalbyteArrayintintbyteArrayint2() throws Exception {
        //Regression for HARMONY-758
        try {
            new NullCipher().update(new byte[1], 1, Integer.MAX_VALUE, 
                    new byte[1], 0);
            fail("Expected IllegalArgumentException was not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    /*
     * Class under test for int doFinal(byte[], int, int, byte[], int)
     */
    @TestTargetNew(
        level = TestLevel.PARTIAL,
        notes = "Exceptions checking missed. Checks inherited method from Cipher.",
        method = "doFinal",
        args = {byte[].class, int.class, int.class, byte[].class, int.class}
    )
    public void testDoFinalbyteArrayintintbyteArrayint3() throws Exception {
        //Regression for HARMONY-758
        try {
            new NullCipher().update(new byte[1], 0, 1, 
                    new byte[0], 0);
            fail("Expected IndexOutOfBoundsException was not thrown");
        } catch (IndexOutOfBoundsException e) {
        }
    }
}
