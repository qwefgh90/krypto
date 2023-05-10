package krypto;

import krypto.algorithm.aria.AriaAlgorithm;
import krypto.exception.WrongFixedKeySize;

import java.security.InvalidKeyException;

/**
 * This class includes a bunch of static factory methods for ARIA
 */
public class AriaAlgorithmFactory {
    public static Algorithm create(String masterKey, int fixedKeySize) throws InvalidKeyException, WrongFixedKeySize {
        checkFixedKeySize(fixedKeySize);
        checkMasterKey(masterKey);
        return new AriaAlgorithm(masterKey, fixedKeySize);
    }
    private static void checkMasterKey(String masterKey) throws InvalidKeyException {
        if(masterKey == null || masterKey.isEmpty())
            throw new InvalidKeyException("masterKey can't be empty.");
    }
    private static void checkFixedKeySize(int fixedKeySize) throws WrongFixedKeySize {
        if(!(fixedKeySize == 256 || fixedKeySize == 192 || fixedKeySize == 128))
            throw new WrongFixedKeySize("fixedKeySize is one of 256, 192 and 128.");
    }
}
