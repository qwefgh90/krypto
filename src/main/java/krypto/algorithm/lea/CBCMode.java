package krypto.algorithm.lea;

import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipherMode;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.symm.LEA;

import static krypto.util.EncryptionUtils.addPKCS7Padding;
import static krypto.util.EncryptionUtils.removePKCS7Padding;

public class CBCMode extends LeaAlgorithm {

    // 객체 생성
    BlockCipherMode cipher = new LEA.CBC();
    byte[] initialVector;
    public CBCMode(String masterKey, int fixedKeySize, byte[] initialVector) {
        super(masterKey, fixedKeySize, Mode.ECB);
        this.initialVector = initialVector;
    }

    @Override
    public byte[] encrypt(byte[] bytes) {
        final byte[] paddedPlainText = addPKCS7Padding(bytes);
        assert paddedPlainText.length % 16 == 0;
        cipher.init(BlockCipher.Mode.ENCRYPT, keyBytes, initialVector);
//        byte[] cipherText = cipher.update();
        byte[] cipherText = cipher.doFinal(paddedPlainText);
        return cipherText;
    }

    @Override
    public byte[] decrypt(byte[] bytes) {
        cipher.init(BlockCipher.Mode.DECRYPT, keyBytes, initialVector);
//        byte[] plainText = cipher.update(bytes);
        byte[] paddedPlainText = cipher.doFinal(bytes);
        return removePKCS7Padding(paddedPlainText);
    }
}
