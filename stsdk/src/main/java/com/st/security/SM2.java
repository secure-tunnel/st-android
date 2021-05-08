package com.st.security;

public class SM2 {
    static {
        System.loadLibrary("bmf_security");
    }

    private SM2() {

    }

    /**
     * 加密
     * @param data
     * @param publicKey
     * @return
     */
    public static byte[] encrypt(byte[] data, byte[] publicKey) {
        return encrypt(data, data.length, publicKey, publicKey.length);
    }

    /**
     * 解密
     * @param data
     * @param privateKey
     * @return
     */
    public static byte[] decrypt(byte[] data, byte[] privateKey) {
        return decrypt(data, data.length, privateKey, privateKey.length);
    }

    /**
     * 私钥签名
     * @param data 待验名数据
     * @param privateKey 私钥 format PEM
     * @return
     */
    public static byte[] sign(byte[] data, byte[] privateKey) {
        return sign(data, data.length, privateKey, privateKey.length);
    }

    /**
     * 公钥验签
     * @param data 待验签数据
     * @param signdat 签名数据
     * @param publicKey 公钥 format PEM
     * @return
     */
    public static boolean verify(byte[] data, byte[] signdat, byte[] publicKey) {
        int ret = verify(data, data.length, signdat, signdat.length, publicKey, publicKey.length);
        return ret == 0 ? true : false;
    }

    private static native byte[] encrypt(byte[] data, int dataLength, byte[] publicKey, int publicKeyLength);
    private static native byte[] decrypt(byte[] data, int dataLength, byte[] privateKey, int privateKeyLength);
    private static native byte[] sign(byte[] data, int dataLength, byte[] privateKey, int privateKeyLength);
    private static native int verify(byte[] data, int dataLength, byte[] signdata, int signdataLength, byte[] publicKey, int publicKeyLength);
}
