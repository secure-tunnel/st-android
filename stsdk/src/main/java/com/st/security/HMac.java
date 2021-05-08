package com.st.security;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>
 * HMac加密类。<br>
 * </p>
 * <p>
 * 说明：HMAC是密钥相关的哈希运算消息认证码（Hash-based Message Authentication Code）,HMAC运算利用哈希算法，以一个密钥和一个消息为输入，生成一个消息摘要作为输出<br>
 * </p>
 * <p>
 * 功能：<br>
 * 1.提供HMac加密接口<br>
 * 2.提供SHA1和MD5加密接口<br>
 * 3.提供RPF加密接口
 * 4.提供一些生成二进制常量的接口<br>
 * </p>
 */
public final class HMac {

	/**
	 * <p>
	 * HMAC encrypt.
	 * </p>
	 * 
	 * @param data source string.
	 * @param key the key.
	 * @param keyMacMode mode of encrypt.
	 * @return encrypted data.
	 * @throws Exception
	 */
	protected static byte[] encryptHMAC(byte[] data, byte[] key, String keyMacMode) throws Exception {
		SecretKey secretKey = new SecretKeySpec(key, keyMacMode);
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		mac.init(secretKey);
		byte[] hmacByt = mac.doFinal(data);
		return hmacByt;
	}
}
