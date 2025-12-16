/*
 * Copyright (C) 2010 The Android Open Source Project
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
package org.conscrypt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class NativeSslTest {

  @Test
  public void toBoringSslGroups_convertsKnownValues() {
    assertArrayEquals(new int[] {NativeConstants.NID_X25519},
      NativeSsl.toBoringSslGroups(new String[] {"X25519"}));
    assertArrayEquals(new int[] {NativeConstants.NID_X25519},
      NativeSsl.toBoringSslGroups(new String[] {"x25519"}));
    assertArrayEquals(new int[] {NativeConstants.NID_X9_62_prime256v1},
      NativeSsl.toBoringSslGroups(new String[] {"P-256"}));
    assertArrayEquals(new int[] {NativeConstants.NID_X9_62_prime256v1},
      NativeSsl.toBoringSslGroups(new String[] {"secp256r1"}));
    assertArrayEquals(new int[] {NativeConstants.NID_secp384r1},
      NativeSsl.toBoringSslGroups(new String[] {"P-384"}));
    assertArrayEquals(new int[] {NativeConstants.NID_secp384r1},
      NativeSsl.toBoringSslGroups(new String[] {"secp384r1"}));
    assertArrayEquals(new int[] {NativeConstants.NID_secp521r1},
      NativeSsl.toBoringSslGroups(new String[] {"P-521"}));
    assertArrayEquals(new int[] {NativeConstants.NID_secp521r1},
      NativeSsl.toBoringSslGroups(new String[] {"secp521r1"}));
    assertArrayEquals(new int[] {NativeConstants.NID_X25519MLKEM768},
      NativeSsl.toBoringSslGroups(new String[] {"X25519MLKEM768"}));
    assertArrayEquals(new int[] {NativeConstants.NID_X25519Kyber768Draft00},
      NativeSsl.toBoringSslGroups(new String[] {"X25519Kyber768Draft00"}));
    assertArrayEquals(new int[] {NativeConstants.NID_ML_KEM_1024},
      NativeSsl.toBoringSslGroups(new String[] {"MLKEM1024"}));
  }

  @Test
  public void toBoringSslGroups_convertsLists() {
    assertArrayEquals(new int[] {NativeConstants.NID_X25519, NativeConstants.NID_X9_62_prime256v1},
      NativeSsl.toBoringSslGroups(new String[] {"X25519", "P-256"}));
  }

  @Test
  public void toBoringSslGroups_ignoresUnknownValues() {
    assertArrayEquals(new int[] {NativeConstants.NID_X25519},
      NativeSsl.toBoringSslGroups(new String[] {"Unknown", "X25519", "Unknown2"}));
  }

  @Test
  public void toBoringSslGroups_throwsIfNoKnownGroupsFound() {
    assertThrows(IllegalArgumentException.class,
      () -> NativeSsl.toBoringSslGroups(new String[] {}));
    assertThrows(IllegalArgumentException.class,
      () -> NativeSsl.toBoringSslGroups(new String[] {"Unknown"}));
    assertThrows(IllegalArgumentException.class,
      () -> NativeSsl.toBoringSslGroups(new String[] {"Unknown", "Unknown2"}));
  }

  @Test
  public void parseNamedGroupsProperty_parsesProperty() {
    assertArrayEquals(new int[] {NativeConstants.NID_X25519},
      NativeSsl.parseNamedGroupsProperty("X25519"));
    assertArrayEquals(new int[] {NativeConstants.NID_X25519, NativeConstants.NID_X9_62_prime256v1},
      NativeSsl.parseNamedGroupsProperty("X25519,P-256"));
    assertArrayEquals(new int[] {NativeConstants.NID_X25519, NativeConstants.NID_X9_62_prime256v1},
      NativeSsl.parseNamedGroupsProperty("X25519, P-256"));
    assertArrayEquals(new int[] {NativeConstants.NID_X25519, NativeConstants.NID_X9_62_prime256v1},
      NativeSsl.parseNamedGroupsProperty("X25519,Unknown,P-256"));
  }

  @Test
  public void parseNamedGroupsProperty_throwsIfNoKnownGroupsFound() {
    assertThrows(NullPointerException.class,
      () -> NativeSsl.parseNamedGroupsProperty(null));
    assertThrows(IllegalArgumentException.class,
      () -> NativeSsl.parseNamedGroupsProperty(""));
    assertThrows(IllegalArgumentException.class,
      () -> NativeSsl.parseNamedGroupsProperty(","));
    assertThrows(IllegalArgumentException.class,
      () -> NativeSsl.parseNamedGroupsProperty(" ,"));
    assertThrows(IllegalArgumentException.class,
      () -> NativeSsl.parseNamedGroupsProperty("Unknown"));
    assertThrows(IllegalArgumentException.class,
      () -> NativeSsl.parseNamedGroupsProperty("Unknown,Unknown2"));
  }

}

