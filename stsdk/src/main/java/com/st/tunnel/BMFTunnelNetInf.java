package com.st.tunnel;

import com.st.BMFResult;

public interface BMFTunnelNetInf {
    public BMFResult send(String gatewayUrl, byte[] data);
}
