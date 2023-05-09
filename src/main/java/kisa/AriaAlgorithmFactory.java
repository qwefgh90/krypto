package kisa;

import kisa.aria.AriaAlgorithm;

import java.security.InvalidKeyException;

public class AriaAlgorithmFactory extends AlgorithmFactory {
    protected String masterKey;
    protected int fixedKeySize;

    public AriaAlgorithmFactory(String masterKey, int fixedKeySize) {
        this.masterKey = masterKey;
        this.fixedKeySize = fixedKeySize;
    }

    @Override
    public Algorithm create() throws InvalidKeyException {
        return new AriaAlgorithm(masterKey, fixedKeySize);
    }
}
