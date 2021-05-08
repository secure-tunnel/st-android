package com.st.tunnel.net;

import com.st.BMFConstans;
import com.st.BMFResult;
import com.st.tunnel.BMFTunnelNetInf;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.Executor;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class TcpSslClient implements BMFTunnelNetInf {
    private static final String TAG = "TcpSslClient";
    private static TcpSslClient instance;
    private static final String[] protocols = new String[]{"TLSv1.2"};
    private static final String[] cihper_suties = new String[]{"TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"};

    // TCP连接句柄
    private SSLSocket mSocket;
    // TCP连接状态
    private boolean mConnState = false;
    // 加密通道链接状态
    private boolean mSecureTunnelState = false;
    private HandshakeCompletedListener handshakeCompletedListener;

    public static TcpSslClient getInstance() {
        if(instance == null) {
            instance = new TcpSslClient();
            // 建立网络连接
//            instance.run();
            // 启动发送数据线程
            instance.sender();
            // 启动接收数据线程
            instance.receiver();
        }
        return instance;
    }

    @Override
    public BMFResult send(String gatewayUrl, byte[] data) {
        try {
            OutputStream outputStream = mSocket.getOutputStream();
            outputStream.write(data);
            outputStream.flush();

            InputStream inputStream = mSocket.getInputStream();
            byte[] bytes = new byte[inputStream.available()];
            inputStream.read(bytes);
            return new BMFResult(bytes);
        } catch (IOException e) {
            e.printStackTrace();
            return new BMFResult(BMFConstans.RESULT_TCP_IO);
        }
    }

    @Override
    public void setHandShakeComplete(HandshakeCompletedListener listener) {
        this.handshakeCompletedListener = listener;
    }

    @Override
    public void startServer() {
        run();
    }

    @Override
    public void setSecureTunnelState(boolean flag) {
        this.mSecureTunnelState = flag;
    }

    /*
        建立网络连接使用TCP SSL
        循环发送数据，循环读取数据
     */
    public void run() {
        try {
            SSLSocketFactory factory = trustAllHttpsCertificates();
            mSocket = (SSLSocket) factory.createSocket(NetConfigure.addr, NetConfigure.port);
            mSocket.setEnabledCipherSuites(cihper_suties);
            mSocket.setEnabledProtocols(protocols);
            mSocket.setKeepAlive(true);
            mSocket.addHandshakeCompletedListener(handshakeCompletedListener);
            mSocket.startHandshake();
        } catch (IOException e) {
            e.printStackTrace();
            mConnState = false;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            mConnState = false;
        } catch (KeyStoreException e) {
            e.printStackTrace();
            mConnState = false;
        } catch (Exception e) {
            e.printStackTrace();
            mConnState = false;
        }
    }

    /**
     * 证书绑定验证
     * @return
     * @throws Exception
     */
    private SSLSocketFactory trustAllHttpsCertificates() throws Exception {
        TrustManager trustManager = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                if (NetConfigure.caflag) {
                    if (chain != null && chain.length >= 1) {
                        X509Certificate x509Certificate = chain[0];
                        x509Certificate.checkValidity();

                        try {
                            // 证书链中的第一个证书由用户所信任的CA颁布()
                            x509Certificate.verify(getRootCertificate().getPublicKey());
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                            throw new CertificateException(
                                    "verify NoSuchAlgorithmException");
                        } catch (InvalidKeyException e) {
                            e.printStackTrace();
                            throw new CertificateException("verify InvalidKeyException");
                        } catch (NoSuchProviderException e) {
                            e.printStackTrace();
                            throw new CertificateException(
                                    "verify NoSuchProviderException");
                        } catch (SignatureException e) {
                            e.printStackTrace();
                            throw new CertificateException("verify SignatureException");
                        } catch (CertificateException e) {
                            throw new CertificateException("证书不合法");
                        }
                    }
                }
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustManager}, null);
        return sslContext.getSocketFactory();
    }

    /**
     * 获取校验证书
     *
     * @return
     */
    private X509Certificate getRootCertificate() {
        X509Certificate x509Certificate = null;
        try {
            InputStream crtInputStream = new BufferedInputStream(NetConfigure.context.getAssets().open(NetConfigure.cacert));
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            x509Certificate = (X509Certificate) factory.generateCertificate(crtInputStream);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return x509Certificate;
    }

    private void sender() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                while(true) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    while (mConnState && mSecureTunnelState) {
                        try {
                            Thread.sleep(100);
                            FuncRecallRecord record = FuncRecallTable.getInstance().findNotSend();
                            if (null == record) {
                                continue;
                            }
                            OutputStream outputStream = mSocket.getOutputStream();
                            outputStream.write(record.getRequestData());
                            outputStream.flush();
                        } catch (IOException e) {
                            e.printStackTrace();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }).start();
    }

    private void receiver() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                while(true) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    while (mConnState && mSecureTunnelState) {
                        try {
                            Thread.sleep(100);
                            InputStream inputStream = mSocket.getInputStream();
//                        inputStream.read()
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }).start();
    }

}
