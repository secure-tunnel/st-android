package com.st;

import com.st.security.MixedModel;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MixedModelTest {
    @Test
    public void encrypt() {
        byte[] buffer = new byte[]{25,52,1,2,3,4,5,6,7,8,9,10,1,1,1,1,3,5,3,5,67,2,43};
        for(int i = 0; i < 17; i++) {
            int modelx = i;//MixedModel.getModelRandomIndex();
            System.out.println(modelx);
            byte[] enc = MixedModel.mixed_encrypt(buffer, modelx);
            byte[] dec = MixedModel.mixed_decrypt(enc, modelx);
            for(int j = 0; j < buffer.length; j++) {
                assertEquals((byte)buffer[j], (byte)dec[j]);
            }
        }

    }
}
