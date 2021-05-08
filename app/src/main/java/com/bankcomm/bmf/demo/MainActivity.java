package com.bankcomm.bmf.demo;

import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.bankcomm.bmf.BMFConstans;
import com.bankcomm.bmf.security.SafeUtil;
import com.bankcomm.bmf.tunnel.Tunnel;
import com.bankcomm.bmlfp.demo.R;

import java.util.concurrent.Executor;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final TextView textView = findViewById(R.id.tv);

        new Executor() {
            @Override
            public void execute(Runnable command) {
                command.run();
            }
        }.execute(new Runnable() {
            @Override
            public void run() {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        byte[] pseudo = new byte[]{12,21,43,53,21,1,42,53,53,5,4,67,5,6,7,8,12,21,43,53,21,1,42,53,53,5,4,67,5,6,7,8};
                        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                                "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEFtXYB9anklMdp9c19S6Gq/lgaxUi\n" +
                                "v6T0BhtziIZx5XKcnj1NnUvbDXLMUBv1v60nxmNYvzACZ1/HMTpmi7jCRg==\n" +
                                "-----END PUBLIC KEY-----";
                        pseudo = SafeUtil.byteAppend(pseudo, publicKey.getBytes());
                        Tunnel.getInstance().init(pseudo).setUrl("http://192.168.31.192:8080/");
                        int result = Tunnel.getInstance().connect();
//                        if(result == BMFConstans.RESULT_OK) {
//                            textView.setText("信道建立成功");
//                        }else{
//                            textView.setText("信道建立失败");
//                        }
                    }
                }).start();

            }
        });
    }


}