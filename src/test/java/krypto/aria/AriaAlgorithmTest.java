package krypto.aria;

import krypto.Algorithm;
import krypto.AriaAlgorithmFactory;
import krypto.exception.WrongFixedKeySize;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

public class AriaAlgorithmTest {
    @Test
    void plainTextLessThan16() throws InvalidKeyException, WrongFixedKeySize {
        Algorithm algo = AriaAlgorithmFactory.create("masterkey", 256);
        String plain = "Hello 안녕";
        byte[] cipherText = algo.encrypt(plain.getBytes());
        byte[] decryptedText = algo.decrypt(cipherText);
        Assertions.assertEquals(new String(decryptedText).getBytes(), plain);
    }

    @Test
    void shortPlainText() throws InvalidKeyException, WrongFixedKeySize {
        Algorithm algo = AriaAlgorithmFactory.create("masterkey", 256);
        String plain = "Hello";
        byte[] cipherText = algo.encrypt(plain.getBytes());
        byte[] decryptedText = algo.decrypt(cipherText);
        Assertions.assertEquals(new String(decryptedText), plain);
    }

    @Test
    void longPlainText() throws InvalidKeyException, WrongFixedKeySize {
        Algorithm algo = AriaAlgorithmFactory.create("masterkey", 256);
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
