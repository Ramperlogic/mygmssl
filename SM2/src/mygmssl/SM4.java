package mygmssl;

import java.io.UnsupportedEncodingException;

public class SM4 {

	public static String encodeCBC(String Key,String M) throws UnsupportedEncodingException {
		byte[] Keybytes = Key.getBytes("utf-8");
		return "0";
	}
	
	public static String decodeCBC(String Key,String S) {
		return "0";
	}
	
	public static String encodeECB(String Key,String M) {
		return "0";
	}
	
	public static String decodeECB(String Key,String S) {
		return "0";
	}
	
	public static void main(String[] args) throws UnsupportedEncodingException {
		System.out.println("-----------------密钥生成-----------------");
        String Key = "1234567899876543";  //ECB 规定16位 秘钥
        System.out.println("Key:" + Key);
        String M = "Man always remember love because of romance only.";
        System.out.println("明文:" + M);
        System.out.println("-----------------CBC加密-----------------");
        
        String S1 = encodeCBC(Key, M);
        System.out.println("密文:"+S1);
        System.out.println("-----------------CBC解密-----------------");
        String S2 = decodeCBC(Key, S1);
        System.out.println("解密结果:"+S2);
        
        System.out.println("--ECB加密--");
        String S3 = encodeECB(Key, M);
        System.out.println("ECB密文:"+S3);
        System.out.println("ECB解密");
        String S4 = decodeECB(Key, S3);
        System.out.println("ECB解密结果:"+S4);
	}
}

