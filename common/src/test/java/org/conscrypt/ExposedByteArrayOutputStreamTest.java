package org.conscrypt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ExposedByteArrayOutputStreamTest {
    @Test
    public void write_works() throws Exception {
        ExposedByteArrayOutputStream outputStream = new ExposedByteArrayOutputStream();

        outputStream.write(new byte[] {1, 2, 3});
        outputStream.write(new byte[] {127, 4, 5, 127}, /* off= */ 1, /* len= */ 2);
        outputStream.write(6);

        assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6}, outputStream.toByteArray());
        assertEquals(6, outputStream.size());
    }

    @Test
    public void reset_works() throws Exception {
        ExposedByteArrayOutputStream outputStream = new ExposedByteArrayOutputStream();
        outputStream.write(new byte[] {1, 2, 3});

        outputStream.reset();
        outputStream.write(new byte[] {7, 8, 9});

        assertArrayEquals(new byte[] {7, 8, 9}, outputStream.toByteArray());
        assertEquals(3, outputStream.size());
    }

    @Test
    public void array_doesNotCopyArray() throws Exception {
        ExposedByteArrayOutputStream outputStream =
                new ExposedByteArrayOutputStream(/* initialCapacity= */ 6);
        byte[] array = outputStream.array();
        assertEquals(6, array.length);
        // Because array is not a copy and there is enough space, write 3 bytes will change array.
        outputStream.write(new byte[] {1, 2, 3});
        assertArrayEquals(new byte[] {1, 2, 3, 0, 0, 0}, array);
    }

    @Test
    public void createWithCapacity_works() throws Exception {
        ExposedByteArrayOutputStream outputStream =
                new ExposedByteArrayOutputStream(/* initialCapacity= */ 77);
        assertEquals(77, outputStream.array().length);
    }

    @Test
    public void capacityTooSmall_resizes() throws Exception {
        ExposedByteArrayOutputStream outputStream =
                new ExposedByteArrayOutputStream(/* initialCapacity= */ 3);
        assertEquals(3, outputStream.array().length);
        outputStream.write(new byte[] {1, 2});
        outputStream.write(new byte[] {3, 4});
        assertTrue(outputStream.array().length > 3);
        assertArrayEquals(new byte[] {1, 2, 3, 4}, outputStream.toByteArray());
    }
}
