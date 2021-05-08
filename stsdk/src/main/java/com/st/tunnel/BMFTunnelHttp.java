package com.st.tunnel;

import com.st.BMFConstans;
import com.st.BMFResult;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class BMFTunnelHttp implements BMFTunnelNetInf {

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
            //设置允许输出
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.connect();

            OutputStream outputStream = conn.getOutputStream();
            outputStream.write(body);
            outputStream.flush();
            outputStream.close();

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
