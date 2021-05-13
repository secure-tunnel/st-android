package com.st.tunnel.net;

import android.net.ssl.SSLSockets;

import com.st.BMFConstans;
import com.st.BMFResult;
import com.st.tunnel.BMFTunnelNetInf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class HttpClient implements BMFTunnelNetInf {

    @Override
    public BMFResult send(String gatewayUrl, byte[] body) {
        byte[] buffer = null;
        int resultCode = BMFConstans.RESULT_OK;
        InputStream inputStream = null;

        try {
            URL url = new URL(gatewayUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.connect();

            int statusCode = conn.getResponseCode();
            if (statusCode == 200) {
                inputStream = conn.getInputStream();
                if (null != inputStream) {
                    buffer = readStream(inputStream);
                }
            }
        }catch (Exception e){
            e.printStackTrace();
            resultCode = BMFConstans.RESULT_HTTP_NET_FAIL;
        }finally {
            if(inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        if(resultCode != BMFConstans.RESULT_OK) {
            return new BMFResult(resultCode);
        }
        if(buffer == null) {
            return new BMFResult(BMFConstans.RESULT_HTTP_NET_FAIL);
        }
        return new BMFResult(buffer);
    }

    @Override
    public void setHandShakeComplete(HandshakeCompletedListener listener) {

    }

    @Override
    public void startServer() {

    }

    @Override
    public void setSecureTunnelState(boolean flag) {

    }

    private static byte[] readStream(InputStream inStream) throws Exception {

        ByteArrayOutputStream outstream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len = -1;
        while ((len = inStream.read(buffer)) != -1) {
            outstream.write(buffer, 0, len);
        }
        outstream.close();
        inStream.close();
        return outstream.toByteArray();
    }

}
