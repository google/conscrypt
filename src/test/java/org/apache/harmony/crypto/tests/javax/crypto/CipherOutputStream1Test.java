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
* @author Alexander Y. Kleymenov
* @version $Revision$
*/

package org.apache.harmony.crypto.tests.javax.crypto;

import dalvik.annotation.TestTargetClass;
import dalvik.annotation.TestInfo;
import dalvik.annotation.TestLevel;
import dalvik.annotation.TestTarget;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Arrays;
import javax.crypto.NullCipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.Cipher;

import junit.framework.TestCase;

@TestTargetClass(CipherOutputStream.class)
/**
 */

public class CipherOutputStream1Test extends TestCase {

    private static class TestOutputStream extends ByteArrayOutputStream {
        private boolean closed = false;

        public void close() {
            closed = true;
        }

        public boolean wasClosed() {
            return closed;
        }
    }

    /**
     * CipherOutputStream(OutputStream os) method testing. Tests that
     * CipherOutputStream uses NullCipher if Cipher is not specified
     * in the constructor.
     */
@TestInfo(
      level = TestLevel.COMPLETE,
      purpose = "",
      targets = {
        @TestTarget(
          methodName = "CipherOutputStream",
          methodArgs = {java.io.OutputStream.class}
        )
    })
    public void testCipherOutputStream() throws Exception {
        byte[] data = new byte[] { -127, -100, -50, -10, -1, 0, 1, 10, 50, 127 };
        TestOutputStream tos = new TestOutputStream();
        CipherOutputStream cos = new CipherOutputStream(tos){};
        cos.write(data);
        cos.flush();
        byte[] result = tos.toByteArray();
        if (!Arrays.equals(result, data)) {
            fail("NullCipher should be used " + "if Cipher is not specified.");
        }
    }

    /**
     * write(int b) method testing. Tests that method writes correct values to
     * the underlying output stream.
     */
@TestInfo(
      level = TestLevel.PARTIAL,
      purpose = "IOException checking missed.",
      targets = {
        @TestTarget(
          methodName = "write",
          methodArgs = {int.class}
        )
    })
    public void testWrite1() throws Exception {
        byte[] data = new byte[] { -127, -100, -50, -10, -1, 0, 1, 10, 50, 127 };
        TestOutputStream tos = new TestOutputStream();
        CipherOutputStream cos = new CipherOutputStream(tos, new NullCipher());
        for (int i = 0; i < data.length; i++) {
            cos.write(data[i]);
        }
        cos.flush();
        byte[] result = tos.toByteArray();
        if (!Arrays.equals(result, data)) {
            fail("CipherOutputStream wrote incorrect data.");
        }
    }

    /**
     * write(byte[] b) method testing. Tests that method writes correct values
     * to the underlying output stream.
     */
@TestInfo(
      level = TestLevel.PARTIAL,
      purpose = "NullPointerException & IOException checking missed.",
      targets = {
        @TestTarget(
          methodName = "write",
          methodArgs = {byte[].class}
        )
    })
    public void testWrite2() throws Exception {
        byte[] data = new byte[] { -127, -100, -50, -10, -1, 0, 1, 10, 50, 127 };
        TestOutputStream tos = new TestOutputStream();
        CipherOutputStream cos = new CipherOutputStream(tos, new NullCipher());
        cos.write(data);
        cos.flush();
        byte[] result = tos.toByteArray();
        if (!Arrays.equals(result, data)) {
            fail("CipherOutputStream wrote incorrect data.");
        }
    }

    /**
     * write(byte[] b, int off, int len) method testing.
     */
@TestInfo(
      level = TestLevel.PARTIAL,
      purpose = "IOException checking missed.",
      targets = {
        @TestTarget(
          methodName = "write",
          methodArgs = {byte[].class, int.class, int.class}
        )
    })
    public void testWrite3() throws Exception {
        byte[] data = new byte[] { -127, -100, -50, -10, -1, 0, 1, 10, 50, 127 };
        TestOutputStream tos = new TestOutputStream();
        CipherOutputStream cos = new CipherOutputStream(tos, new NullCipher());
        for (int i = 0; i < data.length; i++) {
            cos.write(data, i, 1);
        }
        cos.flush();
        byte[] result = tos.toByteArray();
        if (!Arrays.equals(result, data)) {
            fail("CipherOutputStream wrote incorrect data.");
        }
    }

    /**
     * @tests write(byte[] b, int off, int len)
     */
@TestInfo(
      level = TestLevel.PARTIAL,
      purpose = "Regression test. IllegalArgumentException checked.",
      targets = {
        @TestTarget(
          methodName = "write",
          methodArgs = {byte[].class, int.class, int.class}
        )
    })
    public void testWrite4() throws Exception {
        //Regression for HARMONY-758
        try {
            new CipherOutputStream(new BufferedOutputStream((OutputStream) null), new NullCipher()).write(new byte[] {0}, 1, Integer.MAX_VALUE);
        } catch (IllegalArgumentException e) {
        }
    }

    /**
     * @tests write(byte[] b, int off, int len)
     */
@TestInfo(
      level = TestLevel.PARTIAL,
      purpose = "Regression test. Functional.",
      targets = {
        @TestTarget(
          methodName = "write",
          methodArgs = {byte[].class, int.class, int.class}
        )
    })
    public void testWrite5() throws Exception {
        //Regression for HARMONY-758
        Cipher cf = Cipher.getInstance("DES/CBC/PKCS5Padding");
        NullCipher nc = new NullCipher();
        CipherOutputStream stream1 = new CipherOutputStream(new BufferedOutputStream((OutputStream) null), nc);
        CipherOutputStream stream2 = new CipherOutputStream(stream1, cf);
        CipherOutputStream stream3 = new CipherOutputStream(stream2, nc);
        stream3.write(new byte[] {0}, 0, 0);
           //no exception expected
    }

    /**
     * flush() method testing. Tests that method flushes the data to the
     * underlying output stream.
     */
@TestInfo(
      level = TestLevel.PARTIAL,
      purpose = "IOException checking missed.",
      targets = {
        @TestTarget(
          methodName = "flush",
          methodArgs = {}
        )
    })
    public void testFlush() throws Exception {
        byte[] data = new byte[] { -127, -100, -50, -10, -1, 0, 1, 10, 50, 127 };
        TestOutputStream tos = new TestOutputStream();
        CipherOutputStream cos = new CipherOutputStream(tos){};
        cos.write(data);
        cos.flush();
        byte[] result = tos.toByteArray();
        if (!Arrays.equals(result, data)) {
            fail("CipherOutputStream did not flush the data.");
        }
    }

    /**
     * close() method testing. Tests that the method calls the close() method of
     * the underlying input stream.
     */
@TestInfo(
      level = TestLevel.PARTIAL,
      purpose = "IOException checking missed.",
      targets = {
        @TestTarget(
          methodName = "close",
          methodArgs = {}
        )
    })
    public void testClose() throws Exception {
        byte[] data = new byte[] { -127, -100, -50, -10, -1, 0, 1, 10, 50, 127 };
        TestOutputStream tos = new TestOutputStream();
        CipherOutputStream cos = new CipherOutputStream(tos){};
        cos.write(data);
        cos.close();
        byte[] result = tos.toByteArray();
        if (!Arrays.equals(result, data)) {
            fail("CipherOutputStream did not flush the data.");
        }
        assertTrue("The close() method should call the close() method "
                + "of its underlying output stream.", tos.wasClosed());
    }
}

