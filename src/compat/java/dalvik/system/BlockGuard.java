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

public class BlockGuard {
    private static Method m_getThreadPolicy;
    private static Method m_onNetwork;
    static {
        try {
            ClassLoader cl = ClassLoader.getSystemClassLoader();
            Class<?> c_closeGuard = cl.loadClass("dalvik.system.BlockGuard");

            m_getThreadPolicy = c_closeGuard.getDeclaredMethod("getThreadPolicy");
            m_getThreadPolicy.setAccessible(true);

            Class<?> c_policy = cl.loadClass("dalvik.system.BlockGuard.Policy");

            m_onNetwork = c_policy.getDeclaredMethod("onNetwork");
            m_onNetwork.setAccessible(true);
        } catch (Exception ignored) {
        }
    }

    private BlockGuard() {
    }

    public static Policy getThreadPolicy() {
        if (m_getThreadPolicy != null) {
            try {
                Object wrappedPolicy = m_getThreadPolicy.invoke(null);
                return new PolicyWrapper(wrappedPolicy);
            } catch (Exception ignored) {
            }
        }
        return new PolicyWrapper(null);
    }

    public interface Policy {
        void onNetwork();
    }

    public static class PolicyWrapper implements Policy {
        private final Object wrappedPolicy;

        private PolicyWrapper(Object wrappedPolicy) {
            this.wrappedPolicy = wrappedPolicy;
        }

        public void onNetwork() {
            if (m_onNetwork != null && wrappedPolicy != null) {
                try {
                    m_onNetwork.invoke(wrappedPolicy);
                } catch (Exception ignored) {
                }
            }
        }
    }
}
