package com.bankcomm.bmf.utils;

import java.util.HashMap;

public class BMFMemory {

    private HashMap<String, Object> mMap = new HashMap<>();
    private static BMFMemory instance = new BMFMemory();

    private BMFMemory() {}

    public static BMFMemory getInstance() {
        return instance;
    }

    public synchronized HashMap<String, Object> getMap() {
        return mMap;
    }

}
