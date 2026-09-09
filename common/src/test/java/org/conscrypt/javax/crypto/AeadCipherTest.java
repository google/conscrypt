package org.conscrypt.javax.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import org.conscrypt.TestUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.nio.ByteBuffer;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@RunWith(Parameterized.class)
public class AeadCipherTest {
    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    // UTP's log writer attempts to write stdout to a file named after the test.
    // Since Android's Context.openFileOutput forbids path separators (slashes),
    // parameterized tests with slashes in their names (like cipher names) will crash.
    // This helper replaces slashes with underscores in toString() to avoid this.
    private static class CipherParam {
        final String name;
        final Key key;
        final AlgorithmParameterSpec spec;

        CipherParam(String name, Key key, AlgorithmParameterSpec spec) {
            this.name = name;
            this.key = key;
            this.spec = spec;
        }

        @Override
        public String toString() {
            return name.replace('/', '_');
        }
    }

    @Parameterized.Parameters(name = "{0}")
    public static Iterable<CipherParam> ciphers() {
        return Arrays.asList(
                new CipherParam("AES/GCM/NoPadding", new SecretKeySpec(new byte[16], "AES"),
                                new GCMParameterSpec(128, new byte[12])),
                new CipherParam("AES/GCM-SIV/NoPadding", new SecretKeySpec(new byte[16], "AES"),
                                new GCMParameterSpec(128, new byte[12])),
                new CipherParam("ChaCha20/Poly1305/NoPadding",
                                new SecretKeySpec(new byte[32], "ChaCha20"),
                                new IvParameterSpec(new byte[12])));
    }

    private final CipherParam param;

    public AeadCipherTest(CipherParam param) {
        this.param = param;
    }

    @Test
    public void testUpdateAAD_AfterInit() throws Exception {
        Cipher c = Cipher.getInstance(param.name);
        c.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c.updateAAD(new byte[8]);
        c.updateAAD(ByteBuffer.wrap(new byte[8]));
    }

    @Test
    public void testUpdateAAD_AfterUpdate() throws Exception {
        Cipher c = Cipher.getInstance(param.name);
        c.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c.updateAAD(new byte[8]);
        c.update(new byte[8]);
        c.updateAAD(ByteBuffer.wrap(new byte[8]));
    }

    /*
     * Check that two AAD updates are equivalent to one.
     * http://b/27371173
     */
    @Test
    public void testUpdateAAD_Twice() throws Exception {
        Cipher c1 = Cipher.getInstance(param.name);
        Cipher c2 = Cipher.getInstance(param.name);

        c1.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c1.updateAAD(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
        });
        c1.updateAAD(new byte[] {
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        });

        c2.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c2.updateAAD(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        });

        assertArrayEquals(c1.doFinal(), c2.doFinal());
    }

    @Test
    public void testUpdateAAD_ByteBuffer() throws Exception {
        Cipher c1 = Cipher.getInstance(param.name);
        Cipher c2 = Cipher.getInstance(param.name);
        Cipher c3 = Cipher.getInstance(param.name);

        c1.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c1.updateAAD(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        });

        c2.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c2.updateAAD(ByteBuffer.wrap(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        }));

        c3.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        ByteBuffer buf = ByteBuffer.allocateDirect(10);
        buf.put(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        });
        buf.flip();
        c3.updateAAD(buf);

        byte[] c1Final = c1.doFinal();
        byte[] c2Final = c2.doFinal();
        byte[] c3Final = c3.doFinal();
        assertArrayEquals(c1Final, c2Final);
        assertArrayEquals(c1Final, c3Final);
    }

    @Test
    public void testUpdateAAD_ByteBuffer_MultipleUpdates() throws Exception {
        Cipher c1 = Cipher.getInstance(param.name);
        Cipher c2 = Cipher.getInstance(param.name);
        Cipher c3 = Cipher.getInstance(param.name);

        c1.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c1.updateAAD(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
        });
        c1.updateAAD(new byte[] {
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        });

        c2.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c2.updateAAD(ByteBuffer.wrap(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
        }));
        c2.updateAAD(ByteBuffer.wrap(new byte[] {
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        }));

        c3.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        ByteBuffer buf = ByteBuffer.allocateDirect(10);
        buf.put(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        });
        buf.flip();
        buf.limit(5);
        c3.updateAAD(buf);
        buf.limit(10);
        c3.updateAAD(buf);

        byte[] c1Final = c1.doFinal();
        byte[] c2Final = c2.doFinal();
        byte[] c3Final = c3.doFinal();
        assertArrayEquals(c1Final, c2Final);
        assertArrayEquals(c1Final, c3Final);
    }

    @Test
    public void testUpdateAAD_ByteBuffer_MixedCalls() throws Exception {
        Cipher c1 = Cipher.getInstance(param.name);
        Cipher c2 = Cipher.getInstance(param.name);
        Cipher c3 = Cipher.getInstance(param.name);

        c1.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c1.updateAAD(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        });

        c2.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c2.updateAAD(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
        });
        c2.updateAAD(ByteBuffer.wrap(new byte[] {
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        }));

        c3.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        ByteBuffer buf = ByteBuffer.allocateDirect(10);
        buf.put(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        });
        buf.flip();
        buf.limit(5);
        c3.updateAAD(buf);
        c3.updateAAD(new byte[] {
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        });

        byte[] c1Final = c1.doFinal();
        byte[] c2Final = c2.doFinal();
        byte[] c3Final = c3.doFinal();
        assertArrayEquals(c1Final, c2Final);
        assertArrayEquals(c1Final, c3Final);
    }

    @Test
    public void testUpdateAAD_ByteBuffer_Unequal() throws Exception {
        Cipher c1 = Cipher.getInstance(param.name);
        Cipher c2 = Cipher.getInstance(param.name);
        Cipher c3 = Cipher.getInstance(param.name);

        c1.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c1.updateAAD(ByteBuffer.wrap(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
        }));

        c2.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c2.updateAAD(new byte[] {
                0x06,
                0x07,
                0x08,
                0x09,
                0x10,
        });

        c3.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        ByteBuffer buf = ByteBuffer.allocateDirect(10);
        buf.put(new byte[] {
                0x11,
                0x12,
                0x13,
                0x14,
                0x15,
        });
        buf.flip();
        c3.updateAAD(buf);

        byte[] c1Final = c1.doFinal();
        byte[] c2Final = c2.doFinal();
        byte[] c3Final = c3.doFinal();
        assertFalse(Arrays.equals(c1Final, c2Final));
        assertFalse(Arrays.equals(c2Final, c3Final));
        assertFalse(Arrays.equals(c1Final, c3Final));
    }

    /*
     * Check that encryption with old and new instances update correctly.
     * http://b/27324690
     */
    @Test
    public void testReuse() throws Exception {
        Key key2 = differentKey(param.key);
        Cipher c1 = Cipher.getInstance(param.name);
        Cipher c2 = Cipher.getInstance(param.name);

        // Pollute the c1 cipher with AAD
        c1.init(Cipher.ENCRYPT_MODE, param.key, param.spec);
        c1.updateAAD(new byte[] {
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
        });

        // Now init each again and make sure the outputs are the same.  We have to use a
        // different key because reiniting an AEAD cipher with the same key and IV should fail.
        c1.init(Cipher.ENCRYPT_MODE, key2, param.spec);
        c2.init(Cipher.ENCRYPT_MODE, key2, param.spec);

        byte[] aad = new byte[] {
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
        };
        c1.updateAAD(aad);
        c2.updateAAD(aad);

        assertArrayEquals(c1.doFinal(), c2.doFinal());

        // .doFinal should also not allow reuse without re-initialization
        byte[] aad2 = new byte[] {
                0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        };
        try {
            c1.updateAAD(aad2);
            fail("Should not allow updateAAD without re-initialization");
        } catch (IllegalStateException expected) {
        }

        try {
            c1.update(new byte[8]);
            fail("Should not allow update without re-initialization");
        } catch (IllegalStateException expected) {
        }

        try {
            c1.doFinal();
            fail("Should not allow doFinal without re-initialization");
        } catch (IllegalStateException expected) {
        }
    }

    private static Key differentKey(Key key) {
        byte[] keyData = key.getEncoded().clone();
        keyData[0]++;
        return new SecretKeySpec(keyData, key.getAlgorithm());
    }
}
