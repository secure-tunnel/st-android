package com.st.tunnel.net;

import com.st.BMFConstans;
import com.st.BMFResult;
import com.st.security.SM3;
import com.st.security.SafeUtil;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Queue;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * 上层向网络发送数据时，将回调写入函数回调表中
 * 当网络接收数据后从函数回调表中查询对应的回调函数
 */
public class FuncRecallTable {
    private static final String TAG = "FuncRecallTable";

    private static Map<String, FuncRecallRecord> funcRecallMap = new HashMap<>();
    private static BlockingQueue<FuncRecallRecord> queue = new LinkedBlockingQueue<>();

    private static FuncRecallTable instance;

    public static FuncRecallTable getInstance() {
        if(instance == null) {
            instance = new FuncRecallTable();
            /**
             * 请求事件超时处理，暂定3秒
             */
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Thread.sleep(3000);
                        synchronized (queue) {
                            Iterator iterator = funcRecallMap.entrySet().iterator();
                            while (iterator.hasNext()) {
                                FuncRecallRecord record = (FuncRecallRecord) iterator.next();
                                if(record != null) {
                                    if (System.currentTimeMillis() - record.getMills() > 3000) {
                                        record.getRecall().call(new BMFResult(BMFConstans.RESULT_TIMER_FUNCRECALL_CLEAR));
                                        iterator.remove();
                                    }
                                }
                            }
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                }
            }).start();
        }
        return instance;
    }

    private String createSerialId() {
        UUID uuid = UUID.randomUUID();
        Random random = new Random();
        random.setSeed(System.currentTimeMillis());
        return SafeUtil.byte2hex(SM3.hash(new String(uuid.toString() + random.nextInt()).getBytes()));
    }

    public synchronized String add(byte[] data, FuncRecall funcRecall) {
        String id = createSerialId();
        funcRecallMap.put(id, new FuncRecallRecord(id, data, funcRecall));
        try {
            queue.put(new FuncRecallRecord(id, data, funcRecall));
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return id;
    }

    public synchronized void delete(String id) {
        funcRecallMap.remove(id);
    }

    public synchronized FuncRecall find(String id) {
        FuncRecallRecord record = funcRecallMap.get(id);
         if(record != null) {
             return record.getRecall();
         }
         return null;
    }

    public synchronized FuncRecallRecord findNotSend() {
        return queue.poll();
    }
}
