
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;

import net.sf.json.JSONObject;



public class server {

    public static void main(String[] args) throws Exception{
    	String server_state = "on";
    	String server_power = "0";
    	String server_power_off = "1";//关闭服务器的密码
    	System.out.println("启动服务器....");
    	do 
    		server_state = serverProgram(server_power,server_power_off);
    	
    	while(server_state == "on");

    }

    public static String serverProgram(String server_power,String server_power_off) {
        try {
            ServerSocket serverSocket = new ServerSocket(8885);
            //System.out.println("启动服务器....");
            Socket socket = serverSocket.accept();

            String version = "1.0";
            String charset = "UTF-8";
            String user = "ypy";
            String repCode = "hello world";

              BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
              //读取客户端发送来的消息
              String mess = br.readLine();

              System.out.println("我收到了客户端的东西: "+mess);
              JSONObject object = JSONObject.fromObject(mess);
              server_power=(String)object.get("poweroff");  
              
              if(server_power_off.equals(server_power))
              {
            	  socket.close();
            	  serverSocket.close();
            	  System.out.println("已收到服务器关闭指令，现在关闭服务器");
            	  return "off";
              }
              //已接收到客戶端发来的内容，下面进行处理
              //System.out.println(object);
              String reqData=(String)object.get("reqData");    
              System.out.println("reqData="+reqData);
              String rspTime=(String)object.get("rspTime");
              System.out.println(rspTime.format(rspTime));
              System.out.println("rspTime="+rspTime);
              String reqCode=(String)object.get("reqCode");    
              System.out.println("reqCode="+reqCode);
              System.out.println("-----------------------------");
              
              SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");   
      		String repTime = df.format(System.currentTimeMillis()); 
              String jsonRsp= "{\"version\":\""+version+
						"\",\"charset\":\""+charset+
						"\",\"rspData\":{\""+
						"user\":\""+user+
						"\",\"repCode\":\""+repCode+
						"\",\"rspTime\":\""+repTime+
						"\"}}";
              //"{\"version\":\"1.0\",\"charset\":\"UTF-8\",\"rspData\":{\"rspCode\":\"1998125\",\"rspMsg\":\"niiiiiiccccce\"}}";

              BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

              bw.write(jsonRsp+"\n");
              bw.flush();

              
              	bw.close();
              	br.close();
              	socket.close();
              	serverSocket.close();

              
      } catch (IOException e) {
          e.printStackTrace();
          //return "error";
      }
    	return "on";
    }
}
