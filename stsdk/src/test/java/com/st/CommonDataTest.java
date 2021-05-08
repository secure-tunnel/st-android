package com.st;

import com.st.data.CommonData;
import com.st.data.CommonDataEntry;

import org.junit.Assert;
import org.junit.Test;

public class CommonDataTest {

    @Test
    public void packAndUnPack() {
        byte[] v = new byte[]{3,56,23,64,76,2,25,77,43,76,22,87,62,19,21};
        byte[] pack = CommonData.pack(v, true, new byte[40], 1, null, null);
        CommonDataEntry entry = CommonData.unpack(pack);
        Assert.assertArrayEquals(entry.getData(), v);
    }
}
