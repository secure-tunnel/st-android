package com.st.tunnel.net;

public class FuncRecallRecord {
    private long mills;
    private String serialId;
    private FuncRecall recall;
    // TODO 考虑网络自动重试
    private byte[] requestData;
    private boolean isSend;

    public FuncRecallRecord(String serialId, byte[] requestData,  FuncRecall funcRecall) {
        this.mills = System.currentTimeMillis();
        this.serialId = serialId;
        this.recall = funcRecall;
        this.requestData = requestData;
    }

    public long getMills() {
        return mills;
    }

    public void setMills(long mills) {
        this.mills = mills;
    }

    public String getSerialId() {
        return serialId;
    }

    public void setSerialId(String serialId) {
        this.serialId = serialId;
    }

    public FuncRecall getRecall() {
        return recall;
    }

    public void setRecall(FuncRecall recall) {
        this.recall = recall;
    }

    public byte[] getRequestData() {
        return requestData;
    }

    public void setRequestData(byte[] requestData) {
        this.requestData = requestData;
    }

    public boolean isSend() {
        return isSend;
    }

    public void setSend(boolean send) {
        isSend = send;
    }
}
