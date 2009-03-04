/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tests.crypto;

import junit.framework.Test;
import junit.framework.TestSuite;

/**
 * Test suite that includes all tests for the regex project.
 */
public class AllTests {

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AllTests.suite());
//AllTests.java 
    }

    public static Test suite() {
        TestSuite suite = tests.TestSuiteFactory.createTestSuite("All crypto test suites");
        // $JUnit-BEGIN$
        suite.addTest(org.apache.harmony.crypto.tests.javax.crypto.interfaces.AllTests.suite());
        suite.addTest(org.apache.harmony.crypto.tests.javax.crypto.serialization.AllTests.suite());
        suite.addTest(org.apache.harmony.crypto.tests.javax.crypto.spec.AllTests.suite());
        suite.addTest(org.apache.harmony.crypto.tests.javax.crypto.func.AllTests.suite());
        suite.addTest(org.apache.harmony.crypto.tests.javax.crypto.AllTests.suite());
        // $JUnit-END$
        return suite;
    }
}
