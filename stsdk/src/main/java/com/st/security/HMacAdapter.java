package com.st.security;

/**
 * <p>
 * HMac加密适配类。
 * 功能：<br>
 * 1.提供HMac加密接口<br>
 * 2.提供SHA1和MD5加密接口<br>
 * 3.提供RPF加密接口<br>
 * </p>
 */
public final class HMacAdapter {

    /**
     * <p>
     * HMAC encrypt.
     * </p>
     *
     * @param data       source string.
     * @param key        the key.
     * @param keyMacMode mode of encrypt.
     * @return encrypted data.
     * @throws Exception
     */
    protected static byte[] encryptHMAC(byte[] data, byte[] key, String keyMacMode) throws Exception {
        if(keyMacMode == "HmacSM3") {
            return SM3.hmac(data, key);
        }else {
            byte[] hmacByte = null;
            hmacByte = HMac.encryptHMAC(data, key, keyMacMode);
            return hmacByte;
        }
    }
}
