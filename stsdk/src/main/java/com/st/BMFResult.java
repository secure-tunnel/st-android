package com.st;

/**
 * 公共结果
 */
public class BMFResult {
    private int code;
    private byte[] data;

    public BMFResult(int code) {
        this.code = code;
    }

    public BMFResult(byte[] data) {
        this.code = BMFConstans.RESULT_OK;
        this.data = data;
    }

    public BMFResult(int code, byte[] data) {
        this.code = code;
        this.data = data;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }
}
