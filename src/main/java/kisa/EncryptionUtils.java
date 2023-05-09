package kisa;

import java.util.Arrays;

public class EncryptionUtils {

    public static byte[] addPKCS7Padding(byte[] data) {
        int paddingLength = 16 - (data.length % 16);
        byte[] paddingBytes = new byte[paddingLength];
        Arrays.fill(paddingBytes, (byte) paddingLength);
        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        System.arraycopy(paddingBytes, 0, paddedData, data.length, paddingLength);
        return paddedData;
    }

    public static byte[] removePKCS7Padding(byte[] paddedData) {
        int paddingLength = paddedData[paddedData.length - 1];
        byte[] unpaddedData = new byte[paddedData.length - paddingLength];
        System.arraycopy(paddedData, 0, unpaddedData, 0, unpaddedData.length);
        return unpaddedData;
    }
}
