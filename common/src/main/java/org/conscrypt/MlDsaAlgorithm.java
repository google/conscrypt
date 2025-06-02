package org.conscrypt;

/** ML-DSA algorithm. */
public enum MlDsaAlgorithm {
    ML_DSA_65("ML-DSA-65", 1952),
    ML_DSA_87("ML-DSA-87", 2592);

    private final String name;
    private final int publicKeySize;

    private MlDsaAlgorithm(String name, int publicKeySize) {
        this.name = name;
        this.publicKeySize = publicKeySize;
    }

    @Override
    public String toString() {
        return name;
    }

    public int publicKeySize() {
        return publicKeySize;
    }

    public static MlDsaAlgorithm parse(String name) {
        switch (name) {
            case "ML-DSA-65":
                return ML_DSA_65;
            case "ML-DSA-87":
                return ML_DSA_87;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + name);
        }
    }
}
