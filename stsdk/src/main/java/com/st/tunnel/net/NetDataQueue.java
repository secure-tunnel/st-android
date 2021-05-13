package com.st.tunnel.net;

import java.util.LinkedList;
import java.util.Queue;

/**
 * 网络数据队列
 * 用于网络实例从该队列中消费数据
 */
public class NetDataQueue {
    private static final String TAG = "NetDataQueue";

    private static Queue<FuncRecallRecord> queue = new LinkedList<>();


}
