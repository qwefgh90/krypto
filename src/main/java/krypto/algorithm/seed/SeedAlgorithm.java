package krypto.algorithm.seed;

import krypto.Algorithm;
import krypto.util.EncryptionUtils;

/**
 * key size: 128 bits
 */
public abstract class SeedAlgorithm extends Algorithm {
    protected final Mode mode;
    public SeedAlgorithm(String masterKey, Mode mode) {
        super(Kind.SEED, masterKey, EncryptionUtils.getMasterKeyWithFixedLength(masterKey, 128), 128);
        this.mode = mode;
    }

    public Mode getMode() {
        return mode;
    }

    public abstract byte[] encrypt(byte[] bytes);

    public abstract byte[] decrypt(byte[] bytes);

    public enum Mode {
        ECB,
        CBC,
        GCM,
        CCM,
        CMAC,
        CTR
    }
}
