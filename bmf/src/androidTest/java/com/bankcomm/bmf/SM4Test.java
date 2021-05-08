package com.bankcomm.bmf;

import com.bankcomm.bmf.security.SM4;

import org.junit.Assert;
import org.junit.Test;

public class SM4Test {

    @Test
    public void encrypt() {
        byte[] buffer = new byte[]{1,3,52,3,63,64,63,2,54,36,92,67,26,7,46,87,64};
        byte[] key = new byte[]{12,21,43,53,21,1,42,53,53,5,4,67,5,6,7,8};
        byte[] iv = new byte[]{12,21,43,53,21,1,42,53,53,5,4,67,5,6,7,8};
        byte[] enc = SM4.encrypt(buffer, key, iv);
        byte[] dec = SM4.decrypt(enc, key, iv);

        Assert.assertArrayEquals(buffer, dec);
    }
}
