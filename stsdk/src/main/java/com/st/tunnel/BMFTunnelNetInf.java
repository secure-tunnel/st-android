package com.st.tunnel;

import com.st.BMFResult;

import javax.net.ssl.HandshakeCompletedListener;

public interface BMFTunnelNetInf {
    // 用于加密信道发送数据
    BMFResult send(String gatewayUrl, byte[] data);

    void setHandShakeComplete(HandshakeCompletedListener listener);

    void startServer();

    void setSecureTunnelState(boolean flag);
}
