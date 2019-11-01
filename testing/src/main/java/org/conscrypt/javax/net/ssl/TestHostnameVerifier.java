package org.conscrypt.javax.net.ssl;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/**
 * This class implements the simplest possible HostnameVerifier.
 */
public class TestHostnameVerifier implements HostnameVerifier {
    @Override
    public boolean verify(String hostname, SSLSession sslSession) {
        try {
            return verify(hostname, (X509Certificate) sslSession.getPeerCertificates()[0]);
        } catch (SSLException e) {
            return false;
        }
    }

    private boolean verify(String hostname, X509Certificate cert) {
        for (String certHost : getHostnames(cert)) {
            if (certHost.equals(hostname)) {
                return true;
            }
        }
        return false;
    }

    private static final int DNS_NAME_TYPE = 2;

    @SuppressWarnings("MixedMutabilityReturnType")
    private List<String> getHostnames(X509Certificate cert) {
        List<String> result = new ArrayList<String>();
        try {
            Collection<List<?>> altNamePairs = cert.getSubjectAlternativeNames();
            if (altNamePairs != null) {
                for (List<?> altNamePair : altNamePairs) {
                    // altNames are returned as effectively Pair<Integer, String> instances,
                    // where the first member is the type of altName and the second is the name.
                    if (altNamePair.get(0).equals(DNS_NAME_TYPE)) {
                        result.add((String) altNamePair.get(1));
                    }
                }
            }
            return result;
        } catch (CertificateParsingException e) {
            return Collections.emptyList();
        }
    }
}
