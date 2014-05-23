/*
 * Copyright 2014 The Android Open Source Project
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

package dalvik.system;

import java.lang.reflect.Method;

public class CloseGuard {
    private static Method m_get;
    private static Method m_open;
    private static Method m_close;
    private static Method m_warnIfOpen;
    static {
        try {
            Class<?> c_closeGuard = Class.forName("dalvik.system.CloseGuard");

            m_get = c_closeGuard.getDeclaredMethod("get");
            m_get.setAccessible(true);

            m_open = c_closeGuard.getDeclaredMethod("open", String.class);
            m_open.setAccessible(true);

            m_close = c_closeGuard.getDeclaredMethod("close");
            m_close.setAccessible(true);

            m_warnIfOpen = c_closeGuard.getDeclaredMethod("warnIfOpen");
            m_warnIfOpen.setAccessible(true);
        } catch (Exception ignored) {
        }
    }

    private final Object wrappedGuard;

    private CloseGuard(Object wrappedGuard) {
        this.wrappedGuard = wrappedGuard;
    }

    public static CloseGuard get() {
        if (m_get != null) {
            try {
                return new CloseGuard(m_get.invoke(null));
            } catch (Exception ignored) {
            }
        }
        return new CloseGuard(null);
    }

    public void open(String message) {
        if (wrappedGuard != null && m_open != null) {
            try {
                m_open.invoke(wrappedGuard, message);
            } catch (Exception ignored) {
            }
        }
    }

    public void close() {
        if (wrappedGuard != null && m_close != null) {
            try {
                m_close.invoke(wrappedGuard);
            } catch (Exception ignored) {
            }
        }
    }

    public void warnIfOpen() {
        if (wrappedGuard != null && m_warnIfOpen != null) {
            try {
                m_warnIfOpen.invoke(wrappedGuard);
            } catch (Exception ignored) {
            }
        }
    }
}
