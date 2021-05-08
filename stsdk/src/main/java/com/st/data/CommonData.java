package com.st.data;

import com.st.security.MixedModel;
import com.st.security.SM4;
import com.st.security.SafeUtil;

/**
 * 公共数据包头
 */
public class CommonData {

    public static byte[] pack(byte[] data, boolean mixed, byte[] token, int dataType, byte[] key, byte[] iv) {
        byte[] content = data;
        int modelx = MixedModel.getModelRandomIndex();
        int modely = modelx;
        while(modelx == modely) {
            modely = MixedModel.getModelRandomIndex();
        }

        if(dataType > 2) {
            byte[] newkey = key;
            newkey[0] = (byte) modelx;
            newkey[newkey.length - 1] = (byte) modely;
            content = SM4.encrypt(data, newkey ,iv);
        }

        if(mixed) {
            content = MixedModel.mixed_encrypt(content, modelx);
            content = MixedModel.mixed_encrypt(content, modely);
        }

        int totalLen = 1 + 1+7+4+4+1+1+1+40+1+content.length+1;
        byte[] buffer = new byte[totalLen];
        buffer[0] = (byte)0xF0 ;
        buffer[1] = 0x00;
        System.arraycopy(SafeUtil.timestamp(), 0, buffer, 2, 7);
        System.arraycopy(SafeUtil.Int2BytesBigEndian(content.length), 0, buffer, 9, 4);
        System.arraycopy(SafeUtil.Int2BytesBigEndian(data.length), 0, buffer, 13, 4);
        buffer[17] = (byte)modelx;
        buffer[18] = (byte)modely;
        buffer[19] = (byte)dataType;
        if(null == token) {
            token = new byte[40];
        }
        System.arraycopy(token, 0, buffer, 20, 40);
        buffer[60] = (byte)(mixed ? 1 : 0);
        System.arraycopy(content, 0, buffer, 61, content.length);
        buffer[totalLen-1] = (byte) 0xFE;

        return buffer;
    }

    public static CommonDataEntry unpack(byte[] data) {
        if(null == data || data.length < 62 || data[0] != (byte)0xf0 || data[data.length-1] != (byte)0xfe) {
            return null;
        }
        byte[] encryptLenData = new byte[4];
        System.arraycopy(data, 9, encryptLenData, 0, 4);
        int encryptLen = SafeUtil.BytesBigEndian2Int(encryptLenData);
        if(62 + encryptLen != data.length) {
            return null;
        }
        byte[] sourceLenData = new byte[4];
        System.arraycopy(data, 13, sourceLenData, 0, 4);
        int sourceLen = SafeUtil.BytesBigEndian2Int(sourceLenData);
        int modelx = data[17];
        int modely = data[18];
        int dataType = data[19];
        byte[] token = new byte[40];
        System.arraycopy(data, 20, token, 0, 40);
        int mixed = data[60];
        byte[] mixedData = new byte[encryptLen];
        System.arraycopy(data, 61, mixedData, 0, encryptLen);
        if(mixed == 1) {
            mixedData = MixedModel.mixed_decrypt(mixedData, modely);
            mixedData = MixedModel.mixed_decrypt(mixedData, modelx);
        }

        if(sourceLen != mixedData.length) {
            return null;
        }

        return new CommonDataEntry(modelx, modely, token, mixedData, dataType);
    }
}
