package krypto.algorithm.lea;

import krypto.Algorithm;
import krypto.util.EncryptionUtils;

/**
 * Key size: 128, 192, 256 bits
 * Block size: 128 bites
 */
public abstract class LeaAlgorithm extends Algorithm {
    protected final Mode mode;
    public LeaAlgorithm(String masterKey, int fixedKeySize, Mode mode) {
        super(Kind.LEA, masterKey, EncryptionUtils.getMasterKeyWithFixedLength(masterKey, fixedKeySize), fixedKeySize);
        assert fixedKeySize == 256 || fixedKeySize == 192 || fixedKeySize == 128;
        this.mode = mode;
    }

    public Mode getMode() {
        return mode;
    }

    public abstract byte[] encrypt(byte[] bytes);

    public abstract byte[] decrypt(byte[] bytes);

    public enum Mode {
        ECB,
        CBC
    }
}
