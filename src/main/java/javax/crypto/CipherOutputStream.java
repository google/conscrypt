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

package javax.crypto;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import javax.crypto.NullCipher;

/**
 * @com.intel.drl.spec_ref
 */
public class CipherOutputStream extends FilterOutputStream {

    private final Cipher cipher;
    private final byte[] arr = new byte[1];

    /**
     * @com.intel.drl.spec_ref
     */
    public CipherOutputStream(OutputStream os, Cipher c) {
        super(os);
        cipher = c;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    protected CipherOutputStream(OutputStream os) {
        this(os, new NullCipher());
    }

    /**
     * @com.intel.drl.spec_ref
     */
    @Override
    public void write(int b) throws IOException {
        byte[] result;
        arr[0] = (byte) b;
        result = cipher.update(arr);
        if (result != null) {
            out.write(result);
        }
    }

    /**
     * @com.intel.drl.spec_ref
     */
    @Override
    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    /**
     * @com.intel.drl.spec_ref
     */
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (len == 0) {
            return;
        }
        byte[] result = cipher.update(b, off, len);
        if (result != null) {
            out.write(result);
        }
    }

    /**
     * @com.intel.drl.spec_ref
     */
    @Override
    public void flush() throws IOException {
        out.flush();
    }

    /**
     * @com.intel.drl.spec_ref
     */
    @Override
    public void close() throws IOException {
        byte[] result;
        try {
            if (cipher != null) {
                result = cipher.doFinal();
                if (result != null) {
                    out.write(result);
                }
            }
            if (out != null) {
                out.flush();
            }
        } catch (BadPaddingException e) {
            throw new IOException(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new IOException(e.getMessage());
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }
}

