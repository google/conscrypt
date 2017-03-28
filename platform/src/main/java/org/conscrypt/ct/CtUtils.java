package org.conscrypt.ct;

import org.conscrypt.Internal;

/**
 * @hide
 */
@Internal
public final class CtUtils {
    private CtUtils() {}

    public static CTLogStore newLogStore() {
        return new CTLogStoreImpl();
    }

    public static CTPolicy newPolicy(CTLogStore logStore, int minimumLogCount) {
        return new CTPolicyImpl(logStore, minimumLogCount);
    }
}
