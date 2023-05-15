package krypto.lea;

import krypto.Algorithm;
import krypto.LeaAlgorithmFactory;
import krypto.exception.WrongFixedKeySize;
import krypto.exception.WrongInitialVectorLengthException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

public class LeaTestWithCTRTest {
    @Test
    void plainTextLessThan16() throws InvalidKeyException, WrongFixedKeySize, WrongInitialVectorLengthException {
        Algorithm algo = LeaAlgorithmFactory.createWithCTR("masterkey", 256, "1234567812345678".getBytes());
        String plain = "Hello 안녕";
        byte[] cipherText = algo.encrypt(plain.getBytes());
        byte[] decryptedText = algo.decrypt(cipherText);
        Assertions.assertEquals(new String(decryptedText), plain);
    }

    @Test
    void shortPlainText() throws InvalidKeyException, WrongFixedKeySize, WrongInitialVectorLengthException {
        Algorithm algo = LeaAlgorithmFactory.createWithCTR("masterkey", 256, "1234567812345678".getBytes());
        String plain = "Hello";
        byte[] cipherText = algo.encrypt(plain.getBytes());
        byte[] decryptedText = algo.decrypt(cipherText);
        Assertions.assertEquals(new String(decryptedText), plain);
    }

    @Test
    void longPlainText() throws InvalidKeyException, WrongFixedKeySize, WrongInitialVectorLengthException {
        Algorithm algo = LeaAlgorithmFactory.createWithCTR("masterkey", 256, "1234567812345678".getBytes());
        String plain = "Hello 안녕 Bonjour Hola こんにちは 你好";
        StringBuilder repeatedText = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            repeatedText.append(plain);
        }
        byte[] cipherText = algo.encrypt(repeatedText.toString().getBytes());
        byte[] decryptedText = algo.decrypt(cipherText);
        Assertions.assertEquals(new String(decryptedText), repeatedText.toString());
    }
}
