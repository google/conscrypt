package org.conscrypt.testing;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;

public class FailingSniMatcher extends SNIMatcher {
    private FailingSniMatcher() {
        super(0);
    }

    @Override
    public boolean matches(SNIServerName sniServerName) {
        return false;
    }

    public static SNIMatcher create() {
        return new FailingSniMatcher();
    }
}
