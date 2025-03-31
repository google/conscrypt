package org.conscrypt;

import java.io.ByteArrayOutputStream;

/**
 * ByteArrayOutputStream that exposes the underlying byte array.
 */
final class ExposedByteArrayOutputStream extends ByteArrayOutputStream {
    ExposedByteArrayOutputStream() {
        super();
    }

    ExposedByteArrayOutputStream(int initialCapacity) {
        super(initialCapacity);
    }

    byte[] array() {
        return buf;
    }
}
