package com.st.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Random;


/**
 * 该工具类作为加密信道的一些算法函数
 */
public class SafeUtil {

    /**
     * <p>
     * PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR P_SHA-1(S2, label + seed).
     * </p>
     *
     * @param secret the key array.
     * @param label  the label array.
     * @param seed   the seed array.
     * @param length length of result.
     * @return data transformed by PRF.
     */
    public static byte[] PRF(byte[] secret, byte[] label, byte[] seed, int length) throws Exception {
        int secretLen = secret.length;
        boolean is2Times = (secretLen % 2) == 0 ? true : false;
        int splittingLen = secretLen / 2 + (is2Times ? 0 : 1);
        byte[] s1 = new byte[splittingLen];
        byte[] s2 = new byte[splittingLen];
        System.arraycopy(secret, 0, s1, 0, splittingLen);
        if (is2Times) {
            System.arraycopy(secret, splittingLen, s2, 0, splittingLen);
        } else {
            System.arraycopy(secret, splittingLen - 1, s2, 0, splittingLen);
        }
        // label + seed
        byte[] labelAndSeed = new byte[label.length + seed.length];
        System.arraycopy(label, 0, labelAndSeed, 0, label.length);
        System.arraycopy(seed, 0, labelAndSeed, label.length, seed.length);
        byte[] prfMd5;
        byte[] prfSha1;
        // PRF MD5
        prfMd5 = prfHash(s1, labelAndSeed, length, "HmacMD5");
        // PRF SM3
        prfSha1 = prfHash(s2, labelAndSeed, length, "HmacSM3");
        // PRF
        byte[] prf = xor(prfMd5, prfSha1);
        return prf;
    }

    /*
     * @param s1 the key array.
     *
     * @param labelAndSeed the label array & the seed array.
     *
     * @param length length of result.
     *
     * @param keyMacMode weather use SM3 instead of MD5 and SHA
     *
     * @return
     *
     * @throws Exception
     */
    public static byte[] prfHash(byte[] s1, byte[] labelAndSeed, int length, String keyMacMode) throws Exception {
        ArrayList<byte[]> A = new ArrayList<byte[]>();
        A.add(labelAndSeed);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        /*
         * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + HMAC_hash(secret, A(3) + seed) + ...
         */
        while (out.size() < length) {
            int arrSize = A.size();
            byte[] lastA = A.get(arrSize - 1);
            // A(i) = HMAC_hash(secret, A(i-1))
            byte[] currA;
            currA = HMacAdapter.encryptHMAC(lastA, s1, keyMacMode);
            A.add(currA);
            byte[] neoSeed = jogBytes(currA, labelAndSeed);
            byte[] byts;
            byts = HMacAdapter.encryptHMAC(neoSeed, s1, keyMacMode);
            out.write(byts);
        }
        out.flush();
        byte[] outByts = out.toByteArray();
        byte[] prfMd5 = new byte[length];
        System.arraycopy(outByts, 0, prfMd5, 0, prfMd5.length);
        return prfMd5;
    }

    /*
     * @param byts1
     *
     * @param byts2
     *
     * @return
     */
    public static byte[] xor(byte[] byts1, byte[] byts2) {
        int len1 = byts1.length;
        int len2 = byts2.length;
        if (len1 != len2) {
            return null;
        }
        byte[] xor = new byte[len1];
        for (int i = 0; i < len1; i++) {
            xor[i] = (byte) (byts1[i] ^ byts2[i]);
        }
        return xor;
    }

    //产生随机数
    public static String getRandom(int length) {

        String random = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";//产生32为随机数B
        String tmp = "";
        for (int i = 0; i < length; i++) {
            tmp += random.charAt((int) (Math.ceil(Math.random() * 100000000) % random.length()));
        }
        return tmp;
    }

    //取时间戳随机数
    public static String getCurrentTime(int length) {
        String currentTime = String.valueOf(System.currentTimeMillis());
        String tmp = "";
        for (int i = 0; i < length; i++) {
            tmp += currentTime.charAt((int) (Math.ceil(Math.random() * 100000000) % currentTime.length()));
        }
        return tmp;
    }

    //int转byte高位在前
    public static byte[] Int2BytesBigEndian(int value) {
        byte[] tmp = new byte[4];
        tmp[0] = (byte) ((value & 0xFF000000) >> 24);
        tmp[1] = (byte) ((value & 0xFF0000) >> 16);
        tmp[2] = (byte) ((value & 0xFF00) >> 8);
        tmp[3] = (byte) (value & 0xFF);

        return tmp;
    }

    //byte转int高位在前
    public static int BytesBigEndian2Int(byte[] bytes) {
        if (bytes.length < 4) {
            return -1;
        }
        int tmp = (bytes[0] << 24) & 0xFF;
        tmp |= (bytes[1] << 16) & 0xFF;
        tmp |= (bytes[2] << 8) & 0xFF;
        tmp |= bytes[3] & 0xFF;

        return tmp;
    }

    //MD5摘要
    public static byte[] MD5(byte[] src) {
        MessageDigest MD5 = null;
        try {
            MD5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        MD5.update(src);
        return MD5.digest();
    }

    //数组拼接
    public static byte[] byteAppend(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    public static byte[] byteSplit(byte[] data, int pos, int length) {
        byte[] temp = new byte[length];
        System.arraycopy(data, pos, temp, 0, length);
        return temp;
    }

    //随机数副本算法
    public static byte[] changeSeed(byte[] a, byte[] b) {
        byte[] seedcLeft = SM3.hash(a);
        byte[] seedcRight = SM3.hash(b);
        byte[] cleft = Arrays.copyOfRange(seedcLeft, 0, 16);//随机数
        byte[] cright = Arrays.copyOfRange(seedcRight, 0, 16);//随机数
        byte[] seedc = byteAppend(MD5(cleft), MD5(cright));
        return seedc;
    }

    /**
     * jog byte array.
     *
     * @param byts source byte array.
     * @return result.
     */
    public static byte[] jogBytes(byte[]... byts) throws Exception {
        if (byts.length == 0) {
            return null;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] byt : byts) {
            if (byt == null) {
                continue;
            }
            out.write(byt);
        }
        try {
            out.flush();
        } catch (Exception e) {

        }
        byte[] result = out.toByteArray();
        try {
            out.close();
        } catch (Exception e) {

        }
        out = null;
        return result;
    }

    /**
     * 对称密钥生成算法
     *
     * @throws Exception
     */
    public static byte[] generateSymmetricKey(byte raw[]) {
        byte[] A = SM3.hash(raw);
        byte[] B = SM3.hash(byteAppend(A, raw));
        byte[] C = SM3.hash(byteAppend(B, raw));
        return byteAppend(byteAppend(A, B), C);
    }

    // 高位在前
    public static byte[] intToBytes(int value) {
        byte[] src = new byte[4];
        src[0] = (byte) ((value >> 24) & 0xFF);
        src[1] = (byte) ((value >> 16) & 0xFF);
        src[2] = (byte) ((value >> 8) & 0xFF);
        src[3] = (byte) (value & 0xFF);
        return src;
    }

    // 去固定长度的随机数 [0, length)
    public static int getIntRandom(int length) {
        Random random = new Random();
        return random.nextInt(length);
    }

    //将byte[]转换为16进制的字符串
    public static String byte2hex(byte[] b) {
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }
        }
        return hs;
    }

    /**
     * @param len
     * @return
     * @throws Exception
     */
    public static byte[] getClientRandom(int len) {
        // get random. 28 bytes.
        byte[] clientRandom = new byte[len];
        for (int i = 0; i < len; i++) {
            long timeMillis = System.currentTimeMillis();
            int rd = new Random().nextInt();
            byte rdNum = (byte) ((timeMillis + rd) % 256);
            clientRandom[i] = rdNum;
        }
        return clientRandom;
    }

    /**
     * @return
     */
    @SuppressWarnings("deprecation")
    public final static byte[] getClientGMTUnixTime() {
        // get local time.4 bytes.
        Calendar cal = Calendar.getInstance();
        Date date = cal.getTime();
        int hours = date.getHours();
        byte[] clientGmtUnixTime = new byte[4];
        clientGmtUnixTime[0] = (byte) ((hours & 0x0000FF00) >> 8);
        clientGmtUnixTime[1] = (byte) ((hours & 0x000000FF));
        int minutes = date.getMinutes();
        clientGmtUnixTime[2] = (byte) ((minutes & 0x0000FF00) >> 8);
        clientGmtUnixTime[3] = (byte) ((minutes & 0x000000FF));
        return clientGmtUnixTime;
    }

    /**
     * 获取mac地址
     *
     * @return
     */
    public static byte[] getMacAddr() {
        try {
            List<NetworkInterface> all = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface networkInterface : all) {
                if (!networkInterface.getName().equalsIgnoreCase("wlan0")) {
                    continue;
                }
                byte[] macBytes = networkInterface.getHardwareAddress();
                if (macBytes != null) {
                    return macBytes;
                }
                // TODO
            }
        } catch (SocketException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 16进制字符串转byte数组
     *
     * @param hexStr
     * @return
     */
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1) {
            return null;
        }
        hexStr = hexStr.toUpperCase();
        int length = hexStr.length() / 2;
        char[] hexChar = hexStr.toCharArray();
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            result[i] = (byte) (charToByte(hexChar[pos]) << 4 | charToByte(hexChar[pos + 1]));
        }
        return result;
    }

    private static int charToByte(char c) {
        return "0123456789ABCDEF".indexOf(c);
    }

    /**
     * @param secret
     * @return
     * @throws Exception
     */
    public static byte[] getAESKey(final byte[] secret) {
        int len = 32;
        int offset = 0;
        byte[] key = new byte[len];
        System.arraycopy(secret, offset, key, 0, len);
        return key;
    }

    public static byte[] timestamp() {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());

        byte[] buffer = new byte[7];
        buffer[0] = (byte)(calendar.get(Calendar.YEAR)/100);
        buffer[1] = (byte)(calendar.get(Calendar.YEAR)%100);
        buffer[2] = (byte)(calendar.get(Calendar.MONTH));
        buffer[3] = (byte)(calendar.get(Calendar.DAY_OF_MONTH));
        buffer[4] = (byte)(calendar.get(Calendar.HOUR));
        buffer[5] = (byte)(calendar.get(Calendar.MINUTE));
        buffer[6] = (byte)(calendar.get(Calendar.SECOND));
        return buffer;
    }

    public static byte[] getPublicKey(byte[] data) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory
                .generateCertificate(new ByteArrayInputStream(data));
        return cert.getPublicKey().getEncoded();
    }
}
