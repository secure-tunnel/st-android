package com.st.security;

public class SM4 {
    static {
        System.loadLibrary("bmf_security");
    }

    private SM4(){

    }

    public static byte[] encrypt(byte[] data, byte[] key, byte[] iv) {
        return encrypt(data, data.length, key, key.length, iv, iv.length);
    }

    public static byte[] decrypt(byte[] data, byte[] key, byte[] iv) {
        return decrypt(data, data.length, key, key.length, iv, iv.length);
    }


    private static native byte[] encrypt(byte[] data, int dataLength, byte[] key, int keyLength, byte[] iv, int ivLength);
    private static native byte[] decrypt(byte[] data, int dataLength, byte[] key, int keyLength, byte[] iv, int ivLength);

}
