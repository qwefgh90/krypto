package kisa.aria;

import kisa.Algorithm;
import kisa.AriaAlgorithmFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

public class AriaAlgorithmTest {
    @Test
    void plainTextLessThan16() throws InvalidKeyException {
        AriaAlgorithmFactory factory = new AriaAlgorithmFactory("masterkey", 256);
        Algorithm algo = factory.create();
        String plain = "Hello 안녕";
        byte[] cipherText = algo.encrypt(plain.getBytes());
        byte[] decryptedText = algo.decrypt(cipherText);
        Assertions.assertEquals(new String(decryptedText), plain);
    }

    @Test
    void shortPlainText() throws InvalidKeyException {
        AriaAlgorithmFactory factory = new AriaAlgorithmFactory("masterkey", 256);
        Algorithm algo = factory.create();
        String plain = "Hello";
        byte[] cipherText = algo.encrypt(plain.getBytes());
        byte[] decryptedText = algo.decrypt(cipherText);
        Assertions.assertEquals(new String(decryptedText), plain);
    }

    @Test
    void longPlainText() throws InvalidKeyException {
        AriaAlgorithmFactory factory = new AriaAlgorithmFactory("masterkey", 256);
        Algorithm algo = factory.create();
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
