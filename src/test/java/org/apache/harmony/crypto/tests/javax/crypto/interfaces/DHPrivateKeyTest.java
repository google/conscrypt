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
* @author Vera Y. Petrashkova
* @version $Revision$
*/

package org.apache.harmony.crypto.tests.javax.crypto.interfaces;

import dalvik.annotation.TestLevel;
import dalvik.annotation.TestTargetClass;
import dalvik.annotation.TestTargetNew;
import dalvik.annotation.TestTargets;

import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;

import junit.framework.TestCase;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;


/**
 * Tests for <code>DHPrivateKey</code> class field
 * 
 */
@TestTargetClass(DHPrivateKey.class)
public class DHPrivateKeyTest extends TestCase {
    
    /**
     * Constructor for DHPrivateKey.
     * 
     * @param arg0
     */
    public DHPrivateKeyTest(String arg0) {
        super(arg0);
    }

    /**
     * Test for <code>serialVersionUID</code> field
     */  
    @TestTargetNew(
        level = TestLevel.COMPLETE,
        notes = "tests serialVersionUID for a fixed value",
        method = "!field:serialVersionUID"
    )
    public void testField() {
        checkDHPrivateKey key = new checkDHPrivateKey();
        assertEquals("Incorrect serialVersionUID",
                key.getSerVerUID(), //DHPrivateKey.serialVersionUID
                2211791113380396553L);
    }
    
@TestTargets({
    @TestTargetNew(
          level = TestLevel.COMPLETE,
          method = "getX",
          args = {}
        ),
    @TestTargetNew(
          level = TestLevel.COMPLETE,
          clazz = DHKey.class,
          method = "getParams",
          args = {}
        )
    })
    public void test_getParams() throws Exception { 
        KeyPairGenerator kg = KeyPairGenerator.getInstance("DH");
        kg.initialize(512);
        KeyPair kp1 = kg.genKeyPair();
        KeyPair kp2 = kg.genKeyPair();
        DHPrivateKey pk1 = (DHPrivateKey) kp1.getPrivate();
        DHPrivateKey pk2 = (DHPrivateKey) kp2.getPrivate();
        
        assertTrue(pk1.getX().getClass().getCanonicalName().equals("java.math.BigInteger"));
        assertTrue(pk1.getParams().getClass().getCanonicalName().equals("javax.crypto.spec.DHParameterSpec"));
        assertFalse(pk1.getX().equals(pk2.getX()));
        assertTrue(pk1.getX().equals(pk1.getX()));
    }
    
    public class checkDHPrivateKey implements DHPrivateKey {
        public String getAlgorithm() {
            return "SecretKey";
        }
        public String getFormat() {
            return "Format";
        }
        public byte[] getEncoded() {
            return new byte[0];
        }
        public long getSerVerUID() {
            return serialVersionUID;
        }
        public BigInteger getX() {
            return null;
        }
        public DHParameterSpec getParams() {
            return null;
        }
    }
}
