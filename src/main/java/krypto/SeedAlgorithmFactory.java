package krypto;

import krypto.exception.WrongInitialVectorException;
import krypto.algorithm.seed.CBCMode;
import krypto.algorithm.seed.ECBMode;

import java.security.InvalidKeyException;

/**
 * This class includes a bunch of static factory methods for SEED
 */
public class SeedAlgorithmFactory {
    public static Algorithm createWithECB(String masterKey) throws InvalidKeyException {
        checkMasterKey(masterKey);
        return new ECBMode(masterKey);
    }

    /**
     *
     * @param masterKey
     * @param initialVector Initialization vector (IV) parameter with a length of 16 bytes.
     * @return
     */
    public static Algorithm createWithCBC(String masterKey, byte[] initialVector) throws WrongInitialVectorException, InvalidKeyException {
        checkIV(initialVector);
        checkMasterKey(masterKey);
        return new CBCMode(masterKey, initialVector);
    }

    private static void checkMasterKey(String masterKey) throws InvalidKeyException {
        if(masterKey == null || masterKey.isEmpty())
            throw new InvalidKeyException("masterKey can't not be empty.");
    }

    private static void checkIV(byte[] initialVector) throws WrongInitialVectorException {
        if(initialVector.length != 16)
            throw new WrongInitialVectorException("A length of initialVector must be 16 bytes.");
    }
}
