package org.conscrypt.javax.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.conscrypt.TestUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class AeadCipherTest {

  @BeforeClass
  public static void setUp() {
    TestUtils.assumeAllowsUnsignedCrypto();
  }

  @Parameterized.Parameters(name = "{0}")
  public static Iterable<String> ciphers() {
    return Arrays.asList(
      "AES/GCM/NoPadding",
      "AES/GCM-SIV/NoPadding",
      "ChaCha20/Poly1305/NoPadding");
  }

  private final String cipher;
  private byte counter;

  public AeadCipherTest(String cipher) {
    this.cipher = cipher;
  }

  private Key newKey() {
    if (cipher.startsWith("AES/")) {
      byte[] keyData = new byte[16];
      keyData[0] = counter++;
      return new SecretKeySpec(keyData, "AES");
    } else if (cipher.startsWith("ChaCha20/")) {
      byte[] keyData = new byte[32];
      keyData[0] = counter++;
      return new SecretKeySpec(keyData, "ChaCha20");
    } else {
      throw new IllegalStateException("Couldn't generate key for " + cipher);
    }
  }

  private AlgorithmParameterSpec newParamSpec() {
    if (cipher.startsWith("AES/GCM")) {
      byte[] nonce = new byte[12];
      nonce[0] = counter++;
      return new GCMParameterSpec(128, nonce);
    } else if (cipher.startsWith("ChaCha20/")) {
      byte[] nonce = new byte[12];
      nonce[0] = counter++;
      return new IvParameterSpec(nonce);
    } else {
      throw new IllegalStateException("Couldn't generate algorithm parameter spec for " + cipher);
    }
  }

  @Test
  public void testUpdateAAD_AfterInit() throws Exception {
    Cipher c = Cipher.getInstance(cipher);
    c.init(Cipher.ENCRYPT_MODE, newKey());
    c.updateAAD(new byte[8]);
    c.updateAAD(ByteBuffer.wrap(new byte[8]));
  }

  @Test
  public void testUpdateAAD_AfterUpdate() throws Exception {
    Cipher c = Cipher.getInstance(cipher);
    c.init(Cipher.ENCRYPT_MODE, newKey());
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
    Key key = newKey();
    AlgorithmParameterSpec spec = newParamSpec();
    Cipher c1 = Cipher.getInstance(cipher);
    Cipher c2 = Cipher.getInstance(cipher);

    c1.init(Cipher.ENCRYPT_MODE, key, spec);
    c1.updateAAD(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
    });
    c1.updateAAD(new byte[] {
        0x06, 0x07, 0x08, 0x09, 0x10,
    });

    c2.init(Cipher.ENCRYPT_MODE, key, spec);
    c2.updateAAD(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x10,
    });

    assertEquals(Arrays.toString(c1.doFinal()), Arrays.toString(c2.doFinal()));
  }

  @Test
  public void testUpdateAAD_ByteBuffer() throws Exception {
    Key key = newKey();
    AlgorithmParameterSpec spec = newParamSpec();
    Cipher c1 = Cipher.getInstance(cipher);
    Cipher c2 = Cipher.getInstance(cipher);
    Cipher c3 = Cipher.getInstance(cipher);

    c1.init(Cipher.ENCRYPT_MODE, key, spec);
    c1.updateAAD(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x10,
    });

    c2.init(Cipher.ENCRYPT_MODE, key, spec);
    c2.updateAAD(ByteBuffer.wrap(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x10,
    }));

    c3.init(Cipher.ENCRYPT_MODE, key, spec);
    ByteBuffer buf = ByteBuffer.allocateDirect(10);
    buf.put(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x10,
    });
    buf.flip();
    c3.updateAAD(buf);

    byte[] c1Final = c1.doFinal();
    byte[] c2Final = c2.doFinal();
    byte[] c3Final = c3.doFinal();
    assertEquals(Arrays.toString(c1Final), Arrays.toString(c2Final));
    assertEquals(Arrays.toString(c1Final), Arrays.toString(c3Final));
  }

  @Test
  public void testUpdateAAD_ByteBuffer_MultipleUpdates() throws Exception {
    Key key = newKey();
    AlgorithmParameterSpec spec = newParamSpec();
    Cipher c1 = Cipher.getInstance(cipher);
    Cipher c2 = Cipher.getInstance(cipher);
    Cipher c3 = Cipher.getInstance(cipher);

    c1.init(Cipher.ENCRYPT_MODE, key, spec);
    c1.updateAAD(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
    });
    c1.updateAAD(new byte[] {
        0x06, 0x07, 0x08, 0x09, 0x10,
    });

    c2.init(Cipher.ENCRYPT_MODE, key, spec);
    c2.updateAAD(ByteBuffer.wrap(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
    }));
    c2.updateAAD(ByteBuffer.wrap(new byte[] {
        0x06, 0x07, 0x08, 0x09, 0x10,
    }));

    c3.init(Cipher.ENCRYPT_MODE, key, spec);
    ByteBuffer buf = ByteBuffer.allocateDirect(10);
    buf.put(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x10,
    });
    buf.flip();
    buf.limit(5);
    c3.updateAAD(buf);
    buf.limit(10);
    c3.updateAAD(buf);

    byte[] c1Final = c1.doFinal();
    byte[] c2Final = c2.doFinal();
    byte[] c3Final = c3.doFinal();
    assertEquals(Arrays.toString(c1Final), Arrays.toString(c2Final));
    assertEquals(Arrays.toString(c1Final), Arrays.toString(c3Final));
  }

  @Test
  public void testUpdateAAD_ByteBuffer_MixedCalls() throws Exception {
    Key key = newKey();
    AlgorithmParameterSpec spec = newParamSpec();
    Cipher c1 = Cipher.getInstance(cipher);
    Cipher c2 = Cipher.getInstance(cipher);
    Cipher c3 = Cipher.getInstance(cipher);

    c1.init(Cipher.ENCRYPT_MODE, key, spec);
    c1.updateAAD(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x10,
    });

    c2.init(Cipher.ENCRYPT_MODE, key, spec);
    c2.updateAAD(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
    });
    c2.updateAAD(ByteBuffer.wrap(new byte[] {
        0x06, 0x07, 0x08, 0x09, 0x10,
    }));

    c3.init(Cipher.ENCRYPT_MODE, key, spec);
    ByteBuffer buf = ByteBuffer.allocateDirect(10);
    buf.put(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x10,
    });
    buf.flip();
    buf.limit(5);
    c3.updateAAD(buf);
    c3.updateAAD(new byte[] {
        0x06, 0x07, 0x08, 0x09, 0x10,
    });

    byte[] c1Final = c1.doFinal();
    byte[] c2Final = c2.doFinal();
    byte[] c3Final = c3.doFinal();
    assertEquals(Arrays.toString(c1Final), Arrays.toString(c2Final));
    assertEquals(Arrays.toString(c1Final), Arrays.toString(c3Final));
  }

  @Test
  public void testUpdateAAD_ByteBuffer_Unequal() throws Exception {
    Key key = newKey();
    AlgorithmParameterSpec spec = newParamSpec();
    Cipher c1 = Cipher.getInstance(cipher);
    Cipher c2 = Cipher.getInstance(cipher);
    Cipher c3 = Cipher.getInstance(cipher);

    c1.init(Cipher.ENCRYPT_MODE, key, spec);
    c1.updateAAD(ByteBuffer.wrap(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
    }));

    c2.init(Cipher.ENCRYPT_MODE, key, spec);
    c2.updateAAD(new byte[] {
        0x06, 0x07, 0x08, 0x09, 0x10,
    });

    c3.init(Cipher.ENCRYPT_MODE, key, spec);
    ByteBuffer buf = ByteBuffer.allocateDirect(10);
    buf.put(new byte[] {
        0x11, 0x12, 0x13, 0x14, 0x15,
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
    Key key = newKey();
    Key key2 = newKey();
    AlgorithmParameterSpec spec = newParamSpec();
    Cipher c1 = Cipher.getInstance(cipher);
    Cipher c2 = Cipher.getInstance(cipher);

    // Pollute the c1 cipher with AAD
    c1.init(Cipher.ENCRYPT_MODE, key, spec);
    c1.updateAAD(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05,
    });

    // Now init each again and make sure the outputs are the same.  We have to use a
    // different key because reiniting an AEAD cipher with the same key and IV should fail.
    c1.init(Cipher.ENCRYPT_MODE, key2, spec);
    c2.init(Cipher.ENCRYPT_MODE, key2, spec);

    byte[] aad = new byte[] {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
    };
    c1.updateAAD(aad);
    c2.updateAAD(aad);

    assertEquals(Arrays.toString(c1.doFinal()), Arrays.toString(c2.doFinal()));

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

}
