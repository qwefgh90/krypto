package krypto.algorithm.lea;

import krypto.algorithm.lea.impl.kr.re.nsr.crypto.symm.LEA;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipherMode;

import static krypto.util.EncryptionUtils.addPKCS7Padding;
import static krypto.util.EncryptionUtils.removePKCS7Padding;

public class ECBMode extends LeaAlgorithm {

    // 객체 생성
    BlockCipherMode cipher = new LEA.ECB();

    public ECBMode(String masterKey, int fixedKeySize) {
        super(masterKey, fixedKeySize, Mode.ECB);
    }

    @Override
    public byte[] encrypt(byte[] bytes) {
        final byte[] paddedPlainText = addPKCS7Padding(bytes);
        assert paddedPlainText.length % 16 == 0;
        cipher.init(BlockCipher.Mode.ENCRYPT, keyBytes);
//        byte[] cipherText = cipher.update();
        byte[] cipherText = cipher.doFinal(paddedPlainText);
        return cipherText;
    }

    @Override
    public byte[] decrypt(byte[] bytes) {
        cipher.init(BlockCipher.Mode.DECRYPT, keyBytes);
//        byte[] plainText = cipher.update(bytes);
        byte[] paddedPlainText = cipher.doFinal(bytes);
        return removePKCS7Padding(paddedPlainText);
    }
}
