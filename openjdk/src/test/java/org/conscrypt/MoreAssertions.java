/*
 * Copyright (C) 2019 The Android Open Source Project
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class MoreAssertions {
  public static void assertContentsEqual(Collection<?> expected, Collection<?> actual) {
    assertContentsEqual(null, expected, actual);
  }

  public static void assertContentsEqual(
      String message, Collection<?> expected, Collection<?> actual) {
    assertEquals(message, expected.size(), actual.size());
    assertTrue(message, actual.containsAll(expected));
    List<Object> elements = new ArrayList<>(actual);
    elements.removeAll(expected);
    assertEquals(message, 0, elements.size());
  }
}
