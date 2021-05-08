package com.bankcomm.bmf.data;

import com.bankcomm.bmf.security.SM4;
import com.bankcomm.bmf.security.SafeUtil;

/**
 * 公共包解密返回的实体类
 */
public class CommonDataEntry {
    private int modelx;
    private int modely;
    private byte[] token;
    private byte[] data;
    private int dataType;

    public CommonDataEntry(int modelx, int modely, byte[] token, byte[] data, int dataType) {
        this.modelx = modelx;
        this.modely = modely;
        this.token = token;
        this.data = data;
        this.dataType = dataType;
    }


    public int getModelx() {
        return modelx;
    }

    public void setModelx(int modelx) {
        this.modelx = modelx;
    }

    public int getModely() {
        return modely;
    }

    public void setModely(int modely) {
        this.modely = modely;
    }

    public byte[] getToken() {
        return token;
    }

    public void setToken(byte[] token) {
        this.token = token;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public int getDataType() {
        return dataType;
    }

    public void setDataType(int dataType) {
        this.dataType = dataType;
    }

    public byte[] decrypt(byte[] key) {
        byte[] newkey = SafeUtil.byteSplit(key, 0, 32);
        newkey[0] = (byte)modelx;
        newkey[newkey.length-1] =(byte)modely;
        byte[] iv = SafeUtil.byteSplit(key, 32, 16);
        return SM4.decrypt(data, newkey, iv);
    }
}
