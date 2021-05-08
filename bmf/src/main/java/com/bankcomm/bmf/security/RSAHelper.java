package com.bankcomm.bmf.security;

import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;


public class RSAHelper {


    /**
     * 加密。公钥和私钥都可以。使用公钥加密，使用私钥解密。反之亦然
     *
     * @param bytes 待加密数据
     * @param key   公钥或者私钥
     * @return 加密后的byte[]
     * @throws Exception
     */
    protected static byte[] encrypt(byte[] bytes, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypt = cipher.doFinal(bytes);
        return encrypt;
    }

    /**
     * 解密。公钥和私钥都可以。使用公钥加密，使用私钥解密。反之亦然
     *
     * @param bytes 待解密数据
     * @param key   公钥或者私钥
     * @return 解密后的byte[]
     * @throws Exception
     */
    protected static byte[] decrypt(byte[] bytes, Key key) throws Exception {
        Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher2.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypt = cipher2.doFinal(bytes);
        return decrypt;
    }

    /**
     * 根据字符串获取公钥
     *
     * @param keyStr 公钥字符串
     * @return 公钥
     * @throws Exception
     */
    protected static PublicKey getPublicKey(String keyStr) throws Exception {
        byte[] keyBytes = Base64.decode(keyStr, Base64.DEFAULT);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    protected static PublicKey getPublicKey(byte[] signature) throws Exception {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory
                    .generateCertificate(new ByteArrayInputStream(signature));
            byte[] keyData = cert.getPublicKey().getEncoded();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyData);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 根据字符串获取私钥
     *
     * @param keyBytes 私钥字符串
     * @return 私钥
     * @throws Exception
     */
    protected static PrivateKey getPrivateKey(byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }
}
