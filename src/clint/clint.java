package clint;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;

import net.sf.json.JSONObject;

public class clint {
	public static void main(String[] args)
	{
		String reqData = "ypy";
		String poweroff = "1";
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");   
		String rspTime = df.format(System.currentTimeMillis()); 
		String reqCode = "d6760a2ac4f13830d5a6abdce2c688ff0a0a62bd3eccfb7245a95e89eed7a764";
		
		String jsonParams=	"{\"reqData\":\""+reqData+
							"\",\"rspTime\":\""+rspTime+
							"\",\"reqCode\":\""+reqCode+
							"\",\"poweroff\":\""+poweroff+
							"\"}";
		String url = "127.0.0.1";
		String mes = postParams(jsonParams,url);
		
	}
    //使用socket来传输json
    public static String postParams(String jsonParams,String url){

            try {
                //Socket s = new Socket("127.0.0.1",8885);
                Socket s=new Socket(url,8885);

                 //构建IO
                 InputStream is = s.getInputStream();
                 OutputStream os = s.getOutputStream();

                 BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(os));
                 //向服务器端发送一条消息
                 bw.write(jsonParams+"\n");
                 bw.flush();

                 //读取服务器返回的消息
                 BufferedReader br = new BufferedReader(new InputStreamReader(is));
                 String mess = br.readLine();
                 if(mess != null)
                	 System.out.println("服务器发来的消息："+mess);
                 return mess;
            } catch (Exception e) {
                return "error";
            }

    }
    
}
