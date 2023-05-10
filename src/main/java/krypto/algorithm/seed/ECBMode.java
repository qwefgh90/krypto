package krypto.algorithm.seed;

import krypto.algorithm.seed.impl.ecb.KISA_SEED_ECB;

public class ECBMode extends SeedAlgorithm {
    public ECBMode(String masterKey) {
        super(masterKey, Mode.ECB);
    }

    @Override
    public byte[] encrypt(byte[] bytes) {
        return KISA_SEED_ECB.SEED_ECB_Encrypt(keyBytes, bytes, 0, bytes.length);
    }

    @Override
    public byte[] decrypt(byte[] bytes) {
        return KISA_SEED_ECB.SEED_ECB_Decrypt(keyBytes, bytes, 0, bytes.length);
    }
}
