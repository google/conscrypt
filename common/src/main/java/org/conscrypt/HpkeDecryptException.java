package org.conscrypt;

import java.security.GeneralSecurityException;

public class HpkeDecryptException extends GeneralSecurityException {
    private static final long serialVersionUID = 5903211285098828754L;

    public HpkeDecryptException(String msg) {
        super(msg);
    }
}
