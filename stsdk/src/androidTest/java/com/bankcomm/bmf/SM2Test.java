package com.bankcomm.bmf;

import com.st.security.SM2;

import org.junit.Assert;
import org.junit.Test;

public class SM2Test {

    @Test
    public void encryptAndDecrypt() {
        String privatekey = "-----BEGIN EC PARAMETERS-----\n" +
                "BggqgRzPVQGCLQ==\n" +
                "-----END EC PARAMETERS-----\n" +
                "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHcCAQEEINJRYi7nHKfAkCwCKnEAzjLmpnYsj3lXJhU0WGXiNdKooAoGCCqBHM9V\n" +
                "AYItoUQDQgAEFtXYB9anklMdp9c19S6Gq/lgaxUiv6T0BhtziIZx5XKcnj1NnUvb\n" +
                "DXLMUBv1v60nxmNYvzACZ1/HMTpmi7jCRg==\n" +
                "-----END EC PRIVATE KEY-----";
        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEFtXYB9anklMdp9c19S6Gq/lgaxUi\n" +
                "v6T0BhtziIZx5XKcnj1NnUvbDXLMUBv1v60nxmNYvzACZ1/HMTpmi7jCRg==\n" +
                "-----END PUBLIC KEY-----";
        byte[] buffer = new byte[]{1,3,52,3,63,64,63,2,54,36,92,67,26,7,46,87,64};
        byte[] enc = SM2.encrypt(buffer, publicKey.getBytes());
        byte[] dec = SM2.decrypt(enc, privatekey.getBytes());
        Assert.assertArrayEquals(buffer, dec);
    }

    @Test
    public void signAndVerify() {
        String privatekey = "-----BEGIN EC PARAMETERS-----\n" +
                "BggqgRzPVQGCLQ==\n" +
                "-----END EC PARAMETERS-----\n" +
                "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHcCAQEEINJRYi7nHKfAkCwCKnEAzjLmpnYsj3lXJhU0WGXiNdKooAoGCCqBHM9V\n" +
                "AYItoUQDQgAEFtXYB9anklMdp9c19S6Gq/lgaxUiv6T0BhtziIZx5XKcnj1NnUvb\n" +
                "DXLMUBv1v60nxmNYvzACZ1/HMTpmi7jCRg==\n" +
                "-----END EC PRIVATE KEY-----";
        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEFtXYB9anklMdp9c19S6Gq/lgaxUi\n" +
                "v6T0BhtziIZx5XKcnj1NnUvbDXLMUBv1v60nxmNYvzACZ1/HMTpmi7jCRg==\n" +
                "-----END PUBLIC KEY-----";
        byte[] buffer = new byte[]{1,3,52,3,63,64,63,2,54,36,92,67,26,7,46,87,64};
        byte[] signdata = SM2.sign(buffer, privatekey.getBytes());
        Assert.assertEquals(SM2.verify(buffer, signdata, publicKey.getBytes()), true);
    }
}
