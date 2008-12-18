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

package org.apache.harmony.crypto.tests.javax.crypto;

import dalvik.annotation.TestTargetClass;
import dalvik.annotation.TestInfo;
import dalvik.annotation.TestLevel;
import dalvik.annotation.TestTarget;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

import org.apache.harmony.crypto.tests.support.MyKeyGeneratorSpi;

import junit.framework.TestCase;

@TestTargetClass(KeyGeneratorSpi.class)
/**
 * Tests for <code>KeyGeneratorSpi</code> class constructors and methods.
 * 
 */

public class KeyGeneratorSpiTest extends TestCase {
class Mock_KeyGeneratorSpi extends MyKeyGeneratorSpi {

    @Override
    protected SecretKey engineGenerateKey() {
        return super.engineGenerateKey();
    }

    @Override
    protected void engineInit(SecureRandom random) {
        super.engineInit(random);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        super.engineInit(params, random);
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        super.engineInit(keysize, random);
    }
    
}
    /**
     * Constructor for KeyGeneratorSpiTests.
     * 
     * @param arg0
     */
    public KeyGeneratorSpiTest(String arg0) {
        super(arg0);
    }

    /**
     * Test for <code>KeyGeneratorSpi</code> constructor Assertion: constructs
     * KeyGeneratorSpi
     */
@TestInfo(
      level = TestLevel.COMPLETE,
      purpose = "",
      targets = {
        @TestTarget(
          methodName = "KeyGeneratorSpi",
          methodArgs = {}
        )
    })
    public void testKeyGeneratorSpi01() throws InvalidAlgorithmParameterException {
        Mock_KeyGeneratorSpi kgSpi = new Mock_KeyGeneratorSpi();
        assertNull("Not null result", kgSpi.engineGenerateKey());
        try {
            kgSpi.engineInit(77, new SecureRandom());
            fail("IllegalArgumentException must be thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            kgSpi.engineInit(new SecureRandom());
            fail("IllegalArgumentException must be thrown");
        } catch (IllegalArgumentException e) {
        }
        AlgorithmParameterSpec aps = null;        
        try {
            kgSpi.engineInit(aps, new SecureRandom());
            fail("InvalidAlgorithmParameterException must be thrown when parameter is null");            
       } catch (InvalidAlgorithmParameterException e) {
       }
       aps = new APSpecSpi();
       kgSpi.engineInit(aps, new SecureRandom());
    }

}
class APSpecSpi implements AlgorithmParameterSpec {
    
}
