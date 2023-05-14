/*
 * Copyright 2023 qwefgh90
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package krypto.algorithm.aria;

import krypto.Algorithm;
import krypto.algorithm.aria.impl.ARIAEngine;
import krypto.util.EncryptionUtils;

import java.security.InvalidKeyException;

import static krypto.util.EncryptionUtils.addPKCS7Padding;
import static krypto.util.EncryptionUtils.removePKCS7Padding;

/**
 * Padding: PKCS7Padding
 * Block size: 16 bytes
 * information for study: https://jjeong.tistory.com/757
 */
public class AriaAlgorithm extends Algorithm {
    private final ARIAEngine instance;

    public AriaAlgorithm(String masterKey, int fixedKeySize) {
        super(Kind.ARIA, masterKey, EncryptionUtils.getMasterKeyWithFixedLength(masterKey, fixedKeySize), fixedKeySize);
        assert fixedKeySize == 256 || fixedKeySize == 192 || fixedKeySize == 128;

        try {
            instance = new ARIAEngine(fixedKeySize);
            instance.setKey(keyBytes);
            instance.setupRoundKeys();
        } catch (InvalidKeyException e) { //TODO: Will InvalidKeyException be handled by developers ?
            throw new RuntimeException(e);
        }
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
        if (cipherText.length % 16 != 0)
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
