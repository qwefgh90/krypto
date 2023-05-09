package kisa.aria;

import kisa.Algorithm;
import kisa.aria.ARIAEngine;

import java.security.InvalidKeyException;
import java.util.Arrays;

import static kisa.EncryptionUtils.addPKCS7Padding;
import static kisa.EncryptionUtils.removePKCS7Padding;

/**
 * Padding: PKCS7Padding
 * Block size: 16 bytes
 * information for study: https://jjeong.tistory.com/757
 */
public class AriaAlgorithm implements Algorithm {
    private final ARIAEngine instance;
    public AriaAlgorithm(String masterKey, int fixedKeySize) throws InvalidKeyException {
        if (fixedKeySize != 256) {
            throw new RuntimeException("Invalid key size. (support 256 bits)");
        }
        byte[] key = new byte[fixedKeySize];
        //TODO: Designated Hash functions will be needed which make a hash for the key.
        byte[] masterKeyBytes = masterKey.getBytes();
        Arrays.fill(key, (byte) 0);
        for (int i = 0; i < key.length; i++) {
            if (i < masterKeyBytes.length)
                key[i] = masterKeyBytes[i];
        }

        instance = new ARIAEngine(fixedKeySize);
        instance.setKey(key);
        instance.setupRoundKeys();
    }

    @Override
    public byte[] encrypt(byte[] plainText) {
        final byte[] paddedPlainText = addPKCS7Padding(plainText);
        assert paddedPlainText.length % 16 == 0;
        final int lengthWithPadding = paddedPlainText.length;
        final int blockCount = lengthWithPadding / 16;
        final byte[] cipherText = new byte[lengthWithPadding];
        for (int blockNumber = 0; blockNumber < blockCount; blockNumber++) {
            try {
                byte[] cipherBlock = instance.encrypt(paddedPlainText, blockNumber * 16);
                System.arraycopy(cipherBlock, 0, cipherText, blockNumber * 16, 16);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }
        return cipherText;
    }

    @Override
    public byte[] decrypt(byte[] cipherText) {
        if(cipherText.length % 16 != 0)
            throw new RuntimeException("A length of the cipher text has no remainder when divided by 16.");

        int blockCount = cipherText.length / 16;
        byte[] paddedPlainText = new byte[cipherText.length];
        for (int blockNumber = 0; blockNumber < blockCount; blockNumber++) {
            try {
                byte[] block = instance.decrypt(cipherText, blockNumber * 16);
                System.arraycopy(block, 0, paddedPlainText, blockNumber * 16, 16);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        }
        return removePKCS7Padding(paddedPlainText);
    }
}
