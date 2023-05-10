package krypto.algorithm.seed;

import krypto.algorithm.seed.impl.cbc.KISA_SEED_CBC;

public class CBCMode extends SeedAlgorithm{
    byte[] iv;
    public CBCMode(String masterKey, byte[] initialVector) {
        super(masterKey, Mode.CBC);
        assert initialVector.length == 16;
        this.iv = initialVector;
    }

    @Override
    public byte[] encrypt(byte[] bytes) {
        return KISA_SEED_CBC.SEED_CBC_Encrypt(keyBytes, iv, bytes, 0, bytes.length);
    }

    @Override
    public byte[] decrypt(byte[] bytes) {
        return KISA_SEED_CBC.SEED_CBC_Decrypt(keyBytes, iv, bytes, 0, bytes.length);
    }
}
