package com.bankcomm.bmf;

import android.util.Log;

import com.st.security.SM3;

import org.junit.Test;

public class SM3Test {

    @Test
    public void hash() {
        byte[] buffer = new byte[]{1,3,52,3,63,64,63,2,54,36,92,67,26,7,46,87,64};
        byte[] result = SM3.hash(buffer);
        for(int i = 0; i < result.length; i++) {
            Log.d("SM3", String.valueOf(result[i]));
        }
    }
}
