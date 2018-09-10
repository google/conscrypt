package org.conscrypt;

@SuppressWarnings("ImmutableEnumChecker")
public enum BenchmarkProtocol {

    TLSv13_ONLY("TLSv1.3"),
    TLSv12_ONLY("TLSv1.2");

    private final String[] protocols;

    BenchmarkProtocol(String... protocols) {
        this.protocols = protocols;
    }

    public String[] getProtocols() {
        return protocols.clone();
    }
}
