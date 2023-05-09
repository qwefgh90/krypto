package kisa;

public interface Algorithm {
    /**
     *
     * @param bytes any plain text
     * @return
     */
    byte[] encrypt(byte[] bytes);

    /**
     *
     * @param bytes any cipher text which is encrypted with supported algorithms
     * @return
     */
    byte[] decrypt(byte[] bytes);
}
