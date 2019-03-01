/*
 * Copyright (C) 2015 The Android Open Source Project
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

package org.conscrypt.ct;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import org.conscrypt.Internal;

@Internal
public class Serialization {
    private Serialization() {}

    private static final int DER_TAG_MASK = 0x3f;
    private static final int DER_TAG_OCTET_STRING = 0x4;
    private static final int DER_LENGTH_LONG_FORM_FLAG = 0x80;

    public static byte[] readDEROctetString(byte[] input)
            throws SerializationException {
        return readDEROctetString(new ByteArrayInputStream(input));
    }

    public static byte[] readDEROctetString(InputStream input)
            throws SerializationException {
        int tag = readByte(input) & DER_TAG_MASK;
        if (tag != DER_TAG_OCTET_STRING) {
            throw new SerializationException("Wrong DER tag, expected OCTET STRING, got " + tag);
        }
        int length;
        int width = readNumber(input, 1);
        if ((width & DER_LENGTH_LONG_FORM_FLAG) != 0) {
            length = readNumber(input, width & ~DER_LENGTH_LONG_FORM_FLAG);
        } else {
            length = width;
        }

        return readFixedBytes(input, length);
    }

    public static byte[][] readList(byte[] input, int listWidth, int elemWidth)
            throws SerializationException {
        return readList(new ByteArrayInputStream(input), listWidth, elemWidth);
    }

    /**
     * Read a variable length vector of variable sized elements as described by RFC5246 section 4.3.
     * The vector is prefixed by its total length, in bytes and in big endian format,
     * so is each element contained in the vector.
     * @param listWidth the width of the vector's length field, in bytes.
     * @param elemWidth the width of each element's length field, in bytes.
     * @throws SerializationException if EOF is encountered.
     */
    public static byte[][] readList(InputStream input, int listWidth, int elemWidth)
            throws SerializationException {
        ArrayList<byte[]> result = new ArrayList<byte[]>();
        byte[] data = readVariableBytes(input, listWidth);
        input = new ByteArrayInputStream(data);
        try {
            while (input.available() > 0) {
                result.add(readVariableBytes(input, elemWidth));
            }
        } catch (IOException e) {
            throw new SerializationException(e);
        }
        return result.toArray(new byte[result.size()][]);
    }

    /**
     * Read a length-prefixed sequence of bytes.
     * The length must be encoded in big endian format.
     * @param width the width of the length prefix, in bytes.
     * @throws SerializationException if EOF is encountered, or if {@code width} is negative or
     * greater than 4
     */
    public static byte[] readVariableBytes(InputStream input, int width)
            throws SerializationException {
        int length = readNumber(input, width);
        return readFixedBytes(input, length);
    }

    /**
     * Read a fixed number of bytes from the input stream.
     * @param length the number of bytes to read.
     * @throws SerializationException if EOF is encountered.
     */
    public static byte[] readFixedBytes(InputStream input, int length)
            throws SerializationException {
        try {
            if (length < 0) {
                throw new SerializationException("Negative length: " + length);
            }

            byte[] data = new byte[length];
            int count = input.read(data);
            if (count < length) {
                throw new SerializationException("Premature end of input, expected " + length +
                                                 " bytes, only read " + count);
            }
            return data;
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }

    /**
     * Read a number in big endian format from the input stream.
     * This methods only supports a width of up to 4 bytes.
     * @param width the width of the number, in bytes.
     * @throws SerializationException if EOF is encountered, or if {@code width} is negative or
     * greater than 4
     */
    public static int readNumber(InputStream input, int width) throws SerializationException {
        if (width > 4 || width < 0) {
            throw new SerializationException("Invalid width: " + width);
        }

        int result = 0;
        for (int i = 0; i < width; i++) {
            result = (result << 8) | (readByte(input) & 0xFF);
        }

        return result;
    }

    /**
     * Read a number in big endian format from the input stream.
     * This methods supports a width of up to 8 bytes.
     * @param width the width of the number, in bytes.
     * @throws SerializationException if EOF is encountered.
     * @throws IllegalArgumentException if {@code width} is negative or greater than 8
     */
    public static long readLong(InputStream input, int width) throws SerializationException {
        if (width > 8 || width < 0) {
            throw new IllegalArgumentException("Invalid width: " + width);
        }

        long result = 0;
        for (int i = 0; i < width; i++) {
            result = (result << 8) | (readByte(input) & 0xFF);
        }

        return result;
    }

    /**
     * Read a single byte from the input stream.
     * @throws SerializationException if EOF is encountered.
     */
    public static byte readByte(InputStream input) throws SerializationException {
        try {
            int b = input.read();
            if (b == -1) {
                throw new SerializationException("Premature end of input, could not read byte.");
            }
            return (byte)b;
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }

    /**
     * Write length prefixed sequence of bytes to the ouput stream.
     * The length prefix is encoded in big endian order.
     * @param data the data to be written.
     * @param width the width of the length prefix, in bytes.
     * @throws SerializationException if the length of {@code data} is too large to fit in
     * {@code width} bytes or {@code width} is negative.
     */
    public static void writeVariableBytes(OutputStream output, byte[] data, int width)
            throws SerializationException {
        writeNumber(output, data.length, width);
        writeFixedBytes(output, data);
    }

    /**
     * Write a fixed number sequence of bytes to the ouput stream.
     * @param data the data to be written.
     */
    public static void writeFixedBytes(OutputStream output, byte[] data)
            throws SerializationException {
        try {
            output.write(data);
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }

    /**
     * Write a number to the output stream.
     * The number is encoded in big endian order.
     * @param value the value to be written.
     * @param width the width of the encoded number, in bytes
     * @throws SerializationException if the number is too large to fit in {@code width} bytes or
     * {@code width} is negative.
     */
    public static void writeNumber(OutputStream output, long value, int width)
            throws SerializationException {
        if (width < 0) {
            throw new SerializationException("Negative width: " + width);
        }
        if (width < 8 && value >= (1L << (8 * width))) {
            throw new SerializationException(
                    "Number too large, " + value + " does not fit in " + width + " bytes");
        }

        try {
            while (width > 0) {
                long shift = (width - 1) * 8L;
                // Java behaves weirdly if shifting by more than the variable's size
                if (shift < Long.SIZE) {
                    output.write((byte) ((value >> shift) & 0xFF));
                } else {
                    output.write(0);
                }

                width--;
            }
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }
}

