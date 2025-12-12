package org.conscrypt;

public class EchParameters {
    public boolean useEchGrease;

    public byte[] configList;

    public EchParameters() {
        this.useEchGrease = false;
        this.configList = null;
    }

    public EchParameters(boolean useEchGrease) {
        this.useEchGrease = useEchGrease;
        this.configList = null;
    }

    public EchParameters(byte[] configList) {
        this.useEchGrease = false;
        this.configList = configList;
    }

    public EchParameters(boolean useEchGrease, byte[] configList) {
        this.useEchGrease = useEchGrease;
        this.configList = configList;
    }
}
