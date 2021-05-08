package com.bankcomm.bmf.tunnel;

import com.bankcomm.bmf.BMFResult;

public interface BMFTunnelNetInf {
    public BMFResult send(String gatewayUrl, byte[] data);
}
