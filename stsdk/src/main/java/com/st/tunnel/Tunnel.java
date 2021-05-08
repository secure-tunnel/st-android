package com.st.tunnel;

import com.st.BMFConstans;
import com.st.BMFResult;
import com.st.data.CommonData;
import com.st.data.CommonDataEntry;
import com.st.security.SM2;
import com.st.security.SM3;
import com.st.security.SafeUtil;
import com.st.utils.BMFMemory;

import java.security.cert.CertificateException;

/**
 * 通道实例
 * 通道建立后TOKEN、协商D存储在该单例中
 * TOKEN失效则自动重新建立通道
 */
public class Tunnel {

    private static Tunnel mTunnel;
    private byte[] mToken;
    private byte[] mKeyD;
    private BMFTunnelNetInf tunnelNet;
    private String url;

    // 临时变量 每次重连清空
    private byte[] hashRequestHello;
    private byte[] hashRequestExchange;
    private byte[] randomA;
    private byte[] macData;

    public static Tunnel getInstance() {
        if(null == mTunnel) {
            mTunnel = new Tunnel();
        }
        return mTunnel;
    }

    /**
     * SDK通道初始化
     * @param pseduo
     */
    public Tunnel init(byte[] pseduo) {
        // 加载预置伪串到内存中
        BMFMemory.getInstance().getMap().put(BMFConstans.MEM_PSEUDO, pseduo);
        // TODO CA加载用于增强校验服务端返回的用户证书

        return mTunnel;
    }

    public Tunnel setUrl(String url) {
        this.url = url;
        return mTunnel;
    }

    /**
     * 是否开启TCP
     * @param flag
     * @return
     */
    public Tunnel setNetworkTCP(boolean flag) {
        BMFMemory.getInstance().getMap().put(BMFConstans.MEM_TUNNEL_TCP, flag);
        return mTunnel;
    }

    private BMFResult requestHello() {
        byte[] pseudo = (byte[]) BMFMemory.getInstance().getMap().get(BMFConstans.MEM_PSEUDO);
        if(pseudo == null) {
            return new BMFResult(BMFConstans.RESULT_PSEUDO_NOTFOUND, null);
        }
        byte[] pseudoA1 = SafeUtil.byteSplit(pseudo, 0, 32);
        byte[] pseudoPublicKey = SafeUtil.byteSplit(pseudo, 32, pseudo.length - 32);

        // 客户端随机数A
        byte[] clientRandom = SafeUtil.getClientRandom(28);
        byte[] clientTime = SafeUtil.getClientGMTUnixTime();
        randomA = SafeUtil.byteAppend(clientTime, clientRandom);

        macData = new byte[40];
        byte[] tempMacData = SafeUtil.getMacAddr();// 获取mac地址信息
        byte[] temp = new byte[40];
        for (int i = 0; i < 40; i++) {
            temp[i] = 0;
        }
        if (tempMacData == null) {
            macData = temp;
        } else if (tempMacData.length < 40) {
            System.arraycopy(tempMacData, 0, macData, 0, tempMacData.length);
            System.arraycopy(temp, 0, macData, tempMacData.length, 40 - tempMacData.length);
        } else if (tempMacData.length == 40) {
            macData = tempMacData;
        }
        byte[] encypted;
        try {
             encypted = SM2.encrypt(SafeUtil.byteAppend(randomA, macData), pseudoPublicKey);
             if(encypted == null) {
                 return new BMFResult(BMFConstans.RESULT_SM2_ENCRYPT_FAIL, null);
             }
        }catch (Exception e) {
            e.printStackTrace();
            return new BMFResult(BMFConstans.RESULT_SM2_ENCRYPT_FAIL, null);
        }
        byte[] body = SafeUtil.byteAppend(pseudoA1, encypted);
        // 对body计算SM3并保存
        hashRequestHello = SM3.hash(body);
        BMFResult response = new BMFTunnelHttp().send(url, CommonData.pack(body, true, null, 1, null, null));
        if(response.getCode() != BMFConstans.RESULT_OK) {
            return response;
        }
        CommonDataEntry entry = CommonData.unpack(response.getData());
        if(entry == null) {
            return new BMFResult(BMFConstans.RESULT_UNPACK_FAIL);
        }
        mToken = entry.getToken();
        return new BMFResult(BMFConstans.RESULT_OK, entry.getData());
    }

    private BMFResult requestExchange(byte[] data) {
        // 报文体签名
        byte[] signed = SafeUtil.byteSplit(data, 0, 32);
        // 服务端随机数B
        byte[] serverRandomB = SafeUtil.byteSplit(data, 32, 32);
        // 证书
        byte[] serverCertificate = SafeUtil.byteSplit(data, 64, data.length - 64);

        // 计算随机数C(随机数副本算法)
        byte[] clientRandomDataC = SafeUtil.changeSeed(randomA, macData);
        byte[] pre_master_key;
        try {
            // 计算pre_master_key
            pre_master_key = SafeUtil.PRF(serverCertificate, "master_secret".getBytes(),
                    SafeUtil.byteAppend(clientRandomDataC, serverRandomB), 32);
        }catch (Exception e) {
            e.printStackTrace();
            return new BMFResult(BMFConstans.RESULT_PRF_FAIL, null);
        }
        // 客户端随机数D
        byte[] clientRandomDataD = SafeUtil.byteAppend(SafeUtil.getClientGMTUnixTime(),
                SafeUtil.getClientRandom(28));

        byte[] publicKey;
        try {
            publicKey = SafeUtil.getPublicKey(serverCertificate);
        }catch (CertificateException e) {
            e.printStackTrace();
            return new BMFResult(BMFConstans.RESULT_GET_PUBLICKEY_FAIL, null);
        }
        // 通过服务端证书中的公钥加密随机数D产生报文PAC
        byte[] pac;
        try {
            pac = SM2.encrypt(clientRandomDataD, publicKey);
            if(pac == null) {
                return new BMFResult(BMFConstans.RESULT_SM2_ENCRYPT_FAIL, null);
            }
        }catch (Exception e){
            e.printStackTrace();
            return new BMFResult(BMFConstans.RESULT_SM2_ENCRYPT_FAIL, null);
        }
        hashRequestExchange = SM3.hash(pac);
        byte[] key1;
        try {
            byte[] master_key = SafeUtil.PRF(pre_master_key, "master_secret1".getBytes(),
                    SafeUtil.byteAppend(clientRandomDataD, serverRandomB), 32);
            key1 = SafeUtil.PRF(master_key, "key_extension".getBytes(),
                    SafeUtil.byteAppend(clientRandomDataD, serverRandomB), 32);
        }catch (Exception e){
            e.printStackTrace();
            return new BMFResult(BMFConstans.RESULT_PRF_FAIL, null);
        }
        mKeyD = SafeUtil.generateSymmetricKey(key1);
        byte[] requestData = CommonData.pack(pac, true, mToken, 2, null, null);
        BMFResult response = new BMFTunnelHttp().send(url, requestData);
        if(response.getCode() != BMFConstans.RESULT_OK) {
            return response;
        }
        CommonDataEntry entry = CommonData.unpack(response.getData());
        // 对称密钥解密
        byte[] hashSum = entry.decrypt(mKeyD);
        if(hashSum.equals(SafeUtil.byteAppend(hashRequestHello, hashRequestExchange))) {
            return new BMFResult(BMFConstans.RESULT_OK);
        }else {
            return new BMFResult(BMFConstans.RESULT_HASH_TWICE_FAIL);
        }
    }

    public int connect() {
        BMFResult helleResult = requestHello();
        if(helleResult.getCode() != BMFConstans.RESULT_OK) {
            clear();
            return helleResult.getCode();
        }
        BMFResult exchangeResult = requestExchange(helleResult.getData());
        if(exchangeResult.getCode() != BMFConstans.RESULT_OK) {
            clear();
            return exchangeResult.getCode();
        }
        return BMFConstans.RESULT_OK;
    }

    private void clear() {
        mToken = null;
        mKeyD = null;
        hashRequestHello = null;
        hashRequestExchange = null;
        randomA = null;
        macData = null;
    }

    public byte[] send(byte[] data) {
        if(mToken == null) {
            connect();
        }

        return null;
    }
}
