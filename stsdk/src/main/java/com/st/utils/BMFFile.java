package com.st.utils;

import android.content.Context;

import java.io.IOException;
import java.io.InputStream;

public class BMFFile {

    public static final byte[] readAssetFile(Context context, String filePath) {
        byte[] bytes = null;
        if (null == filePath || filePath.isEmpty()) {
            return bytes;
        }
        InputStream inputStream = null;
        try {
            inputStream = context.getAssets().open(filePath);
            int len = inputStream.available();
            bytes = new byte[len];
            inputStream.read(bytes);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return bytes;
    }
}
