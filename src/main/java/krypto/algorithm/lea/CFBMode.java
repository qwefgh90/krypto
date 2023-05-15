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

package krypto.algorithm.lea;

import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipher;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.BlockCipherMode;
import krypto.algorithm.lea.impl.kr.re.nsr.crypto.symm.LEA;

import static krypto.util.EncryptionUtils.addPKCS7Padding;
import static krypto.util.EncryptionUtils.removePKCS7Padding;

public class CFBMode extends LeaAlgorithm {

    // 객체 생성
    BlockCipherMode cipher = new LEA.CFB();
    byte[] initialVector;
    public CFBMode(String masterKey, int fixedKeySize, byte[] initialVector) {
        super(masterKey, fixedKeySize, Mode.CFB);
        this.initialVector = initialVector;
    }

    @Override
    public byte[] encrypt(byte[] bytes) {
        final byte[] paddedPlainText = addPKCS7Padding(bytes);
        assert paddedPlainText.length % 16 == 0;
        cipher.init(BlockCipher.Mode.ENCRYPT, keyBytes, initialVector);
        byte[] cipherText = cipher.doFinal(paddedPlainText);
        return cipherText;
    }

    @Override
    public byte[] decrypt(byte[] bytes) {
        cipher.init(BlockCipher.Mode.DECRYPT, keyBytes, initialVector);
        byte[] paddedPlainText = cipher.doFinal(bytes);
        return removePKCS7Padding(paddedPlainText);
    }
}
