package com.st.security;

public class SM3 {
    private static final int BLOCK_LENGTH = 64;

    static {
        System.loadLibrary("bmf_security");
    }

    private SM3(){

    }

    public static byte[] hash(byte[] data) {
        return hash(data, data.length);
    }

    public static byte[] hmac(byte[] data, byte[] key) {
        byte[] sm3_key;
        byte[] structured_key = new byte[BLOCK_LENGTH];
        byte[] IPAD = new byte[BLOCK_LENGTH];
        byte[] OPAD = new byte[BLOCK_LENGTH];
        if(key.length > BLOCK_LENGTH) {
            sm3_key = hash(key);
            System.arraycopy(sm3_key, 0, structured_key, 0, sm3_key.length);
        }else{
            System.arraycopy(key, 0, structured_key, 0, key.length);
        }
        /*
            让处理之后的key与ipad（分组长度的0x36）做异或运算
        */
        for(int i = 0; i <BLOCK_LENGTH; i++) {
            IPAD[i] = 0x36;
            OPAD[i] = 0x5c;
        }
        byte[] ipadKey = new byte[BLOCK_LENGTH];
        for(int i = 0; i < BLOCK_LENGTH; i++) {
            ipadKey[i] = (byte) (structured_key[i] ^ IPAD[i]);
        }
        byte[] t3 = new byte[BLOCK_LENGTH + data.length];
        System.arraycopy(ipadKey, 0, t3, 0, ipadKey.length);
        System.arraycopy(data, 0, t3, ipadKey.length, data.length);
        byte[] t4 = hash(t3);
        byte[] opadKey = new byte[BLOCK_LENGTH];
        for(int i = 0; i < BLOCK_LENGTH; i++) {
            opadKey[i] = (byte) (structured_key[i] ^ OPAD[i]);
        }
        byte[] t6 = new byte[BLOCK_LENGTH + t4.length];
        System.arraycopy(opadKey, 0, t6, 0, opadKey.length);
        System.arraycopy(t4, 0, t6, opadKey.length, t4.length);
        return hash(t6);
    }

    private static native byte[] hash(byte[] data, int dataLength);
}
