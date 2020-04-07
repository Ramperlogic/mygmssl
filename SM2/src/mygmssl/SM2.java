package mygmssl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class SM2 {
	
	private static ECPoint G;
	private static boolean debug = true;
	private static final int DIGEST_LENGTH = 32;
	/*
	 * ECCurve.Fp
	 *	public ECCurve.Fp(java.math.BigInteger q,
     *            java.math.BigInteger a,
     *            java.math.BigInteger b)
	 */
	private static ECCurve.Fp curveFp;
	private static ECCurve.F2m curveF2m;
	private static String type = null;
	/*
	 * ECCurve.F2m
	 * public ECCurve.F2m(int m,
     *             int k,
     *             java.math.BigInteger a,
     *             java.math.BigInteger b)
	 * Constructor for Trinomial Polynomial Basis (TPB).
	 * Parameters:
	 *  			m - The exponent m of F2m.
     *  			k - The integer k where xm + xk + 1 represents
	 *  			 the reduction polynomial f(z).
	 *  			a - The coefficient a in the Weierstrass equation 
	 *  			 for non-supersingular elliptic curves over F2m.
	 *  			b - The coefficient b in the Weierstrass equation 
	 *  			 for non-supersingular elliptic curves over F2m.
	 *  			k也可写作k1,k2,k3，为五项式多项式基础（PPB）的构造函数
	 */
	private static ECDomainParameters ecc_bc_spec;
	private static BigInteger nFp = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "7203DF6B" + "21C6052B" + "53BBF409" + "39D54123", 16);
	private static BigInteger pFp = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFF", 16);
	private static BigInteger aFp = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFC", 16);
	private static BigInteger bFp = new BigInteger(
			"28E9FA9E" + "9D9F5E34" + "4D5A9E4B" + "CF6509A7" + "F39789F5" + "15AB8F92" + "DDBCBD41" + "4D940E93", 16);
	private static BigInteger gxFp = new BigInteger(
			"32C4AE2C" + "1F198119" + "5F990446" + "6A39C994" + "8FE30BBF" + "F2660BE1" + "715A4589" + "334C74C7", 16);
	private static BigInteger gyFp = new BigInteger(
			"BC3736A2" + "F4F6779C" + "59BDCEE3" + "6B692153" + "D0A9877C" + "C62A4740" + "02DF32E5" + "2139F0A0", 16);
	private static int w = (int) Math.ceil(nFp.bitLength() * 1.0 / 2) - 1;
	
	private static BigInteger nF2m = new BigInteger(
			"7FFFFFFF"+"FFFFFFFF"+"FFFFFFFF"+"FFFFFFFF"+"BC972CF7"+"E6B6F900"+"945B3C6A"+"0CF6161D", 16);
	private static BigInteger aF2m = new BigInteger(
			"00000000" + "00000000" + "00000000" + "00000000" + "00000000" + "00000000" + "00000000" + "00000000",16);
	private static BigInteger bF2m = new BigInteger(
			"00"+"E78BCD09"+"746C2023"+"78A7E72B"+"12BCE002"+"66B9627E"+"CB0B5A25"+"367AD1AD"+"4CC6242B", 16);
	private static BigInteger gxF2m = new BigInteger(
			"00"+"CDB9CA7F"+"1E6B0441"+"F658343F"+"4B10297C"+"0EF9B649"+"1082400A"+"62E7A748"+"5735FADD", 16);
	private static BigInteger gyF2m = new BigInteger(
			"01"+"3DE74DA6"+"5951C4D7"+"6DC89220"+"D5F7777A"+"611B1C38"+"BAE260B1"+"75951DC8"+"060C2B3E", 16);
	private static int m = 193;
	private static int k = 15;
	
	public SM2() {
		
		curveFp = new ECCurve.Fp(pFp, // q
				aFp, // a
				bFp); // b
	
		curveF2m = new ECCurve.F2m(m, k, aF2m, bF2m);
		if(type.equals("Fp"))
		{
			G = curveFp.createPoint(gxFp, gyFp ,false);
			ecc_bc_spec = new ECDomainParameters(curveFp, G, nFp);
		}
		else
		{
			G = curveF2m.createPoint(gxF2m, gyF2m, false);
			ecc_bc_spec = new ECDomainParameters(curveF2m, G, nF2m);
		}
			
			
		
	}
	//此处做了修改，增加了一个getter方法---姚
		public ECCurve.Fp getCurveFp() {
			return curveFp;
		}
		public ECCurve.F2m getCurveF2m()
		{
			return curveF2m;
		}
	private static boolean checkPublicKeyFp(ECPoint publicKey) {
		//Fp方法：
		//验证P不是无穷远点
		if (!publicKey.isInfinity()) {

			BigInteger x = publicKey.getX().toBigInteger();
			BigInteger y = publicKey.getY().toBigInteger();

			if (between(x, new BigInteger("0"), pFp) && between(y, new BigInteger("0"), pFp)) {
				//验证公钥P的坐标xP和yP是域Fp中的元素
				BigInteger xResult = x.pow(3).add(aFp.multiply(x)).add(bFp).mod(pFp);
				//验证yP^2≡xP^3+axP+b mod P
				if (debug)
					System.out.println("xResult: " + xResult.toString());

				BigInteger yResult = y.pow(2).mod(pFp);

				if (debug)
					System.out.println("yResult: " + yResult.toString());

				if (yResult.equals(xResult) && publicKey.multiply(nFp).isInfinity()) {
					return true;
				}
			}
		}
		return false;
	}
	
	private static boolean checkPublicKeyF2m(ECPoint publicKey) {
		//F2m方法
		//验证P不是无穷远
		if(!publicKey.isInfinity()) {
			////验证公钥P的坐标xP和yP是域Fp中的元素
			BigInteger x = publicKey.getX().toBigInteger();
			BigInteger y = publicKey.getY().toBigInteger();
			
			if (x.bitLength()==m && y.bitLength()==m) 
			{
				//在F2m中验证yP^2+xPyP=xP^3+axP^2+b
				BigInteger xResult = y.pow(2).add(x.multiply(bF2m));
				BigInteger yResult = x.pow(3).add(aF2m.multiply(x.pow(2))).add(bF2m);
				if(debug)
				{
					System.out.println("xResult = "+xResult);
					System.out.println("yResult = "+yResult);
				}
				if(xResult.equals(yResult))//验证[n]P=O
				{
					if (publicKey.multiply(nF2m).isInfinity()) 
					{
						return true;
					}
				}
			}
			
		}
			return false;
	}
	private static byte[] ZA(String IDA, ECPoint PublicKey) {
		/*
		 	SM2数字签名算法中，作为签名者的用户A的密钥对包括其私钥dA和公钥PA=[dA]G=(xA，yA)，
			用户A具有位长为entlenA的可辨别标识IDA，记ENTLA是由整数entlenA转换而成的2B
			数据，签名者和验证者都需要用密码杂凑算法求得用户A的杂凑值
			ZA=H256(ENTLA||IDA||a||b||xG||yG||xA||yA)．SM2数字签名算法规定H256为
			SM3密码杂凑算法．
		*/
		byte[] idBytes = IDA.getBytes();
		int entlenA = idBytes.length * 8;
		byte[] ENTLA = new byte[] { (byte) (entlenA & 0xFF00), (byte) (entlenA & 0x00FF) };
		byte[] ZA = sm3hash(ENTLA, idBytes, ecc_bc_spec.getCurve().getA().toBigInteger().toByteArray(), 
				ecc_bc_spec.getCurve().getB().toBigInteger().toByteArray(),
				ecc_bc_spec.getG().getX().toBigInteger().toByteArray(),
				ecc_bc_spec.getG().getY().toBigInteger().toByteArray(),
				PublicKey.getX().toBigInteger().toByteArray(),
				PublicKey.getY().toBigInteger().toByteArray());
		return ZA;
	}
	public static class Signature {
		BigInteger r;
		BigInteger s;

		public Signature(BigInteger r, BigInteger s) {
			this.r = r;
			this.s = s;
		}

		public String toString() {
			return r.toString(16) + "," + s.toString(16);
		}
	}
	private static boolean between(BigInteger param, BigInteger min, BigInteger max) {
		if (param.compareTo(min) >= 0 && param.compareTo(max) < 0) {
			return true;
		} else {
			return false;
		}
	}
	private static byte[] KDF(byte[] Z, int klen) {
		int ct = 1;
		int end = (int) Math.ceil(klen * 1.0 / 32);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			for (int i = 1; i < end; i++) {
				baos.write(sm3hash(Z, SM3.toByteArray(ct)));
				ct++;
			}
			byte[] last = sm3hash(Z, SM3.toByteArray(ct));
			if (klen % 32 == 0) {
				baos.write(last);
			} else
				baos.write(last, 0, klen % 32);
			return baos.toByteArray();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	private static BigInteger randomgenerator(BigInteger max) {
		Random random = new Random();
		BigInteger r = new BigInteger(256, random);
		// int count = 1;

		while (r.compareTo(max) >= 0) {
			r = new BigInteger(128, random);
			// count++;
		}

		// System.out.println("count: " + count);
		return r;
	}
	private static byte[] sm3hash(byte[]... params) {
		byte[] res = null;
		try {
			res = SM3.hash(join(params));
		} catch (IOException e) {
			//  Auto-generated catch block
			e.printStackTrace();
		}
		return res;
	}
	private static byte[] join(byte[]... params) {//pinjie
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] res = null;
		try {
			for (int i = 0; i < params.length; i++) {
				baos.write(params[i]);
			}
			res = baos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return res;
	}
	public static void printHexString(byte[] b) {
		for (int i = 0; i < b.length; i++) {
			String hex = Integer.toHexString(b[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			System.out.print(hex.toUpperCase());
		}
		System.out.println();
	}
	private boolean allZero(byte[] buffer) {
		for (int i = 0; i < buffer.length; i++) {
			if (buffer[i] != 0)
				return false;
		}
		return true;
	}
	public SM2KeyPair generateKeyPair() {

		BigInteger d = randomgenerator(ecc_bc_spec.getN().subtract(new BigInteger("1")));

		SM2KeyPair keyPair = new SM2KeyPair(G.multiply(d), d);//推测F2m在此处出了问题，生成的密钥对的publicKey中X，Y值不相等

		if(type.equals("Fp"))
		{
			if (checkPublicKeyFp(keyPair.getPublicKey())) {
				if (debug)
					System.out.println("密钥对生成成功！");
				return keyPair;
			} else {
				System.err.println("密钥对生成失败");
				return null;
			}
		}
		else
		{
			if (checkPublicKeyF2m(keyPair.getPublicKey())) {
				if (debug)
					System.out.println("密钥对生成成功！");
				return keyPair;
			} else {
				System.err.println("密钥对生成失败");
				return null;
			}
		}
	}

	public byte[] encode(String input, ECPoint publicKey){
		byte[] inputBuffer = input.getBytes();
		if(debug)
		{
			System.out.print("publicKey.Hex = ");
			printHexString(inputBuffer);
		}
		int klen = inputBuffer.length;//示要获得的密钥数据的位长，要求该值小于(2^32-1)*v；
		byte[] C1Buffer;
		ECPoint kpb;
		byte[] t;
		//密钥派生
    	//int v = 256;	//SM2算法目前版本中v只取为256
		
    	
    do{
    	//A1:用随机数发生器产生随机数
    	BigInteger k = randomgenerator(ecc_bc_spec.getN());//
    	if(debug)
    	{
    		System.out.print("k  = ");
			printHexString(k.toByteArray());
    	}
    	//A2:计算椭圆曲线点C1=[k]G=(x1,y1)，将C1的数据类型转换为比特串；
    	ECPoint C1 =   G.multiply(k);//
    	C1Buffer =  C1.getEncoded();
    	if (debug) {
			System.out.print("C1 = ");
			printHexString(C1Buffer);
		}
		
    	//A3:计算椭圆曲线点S=[h]PB，若s是无穷远点，则报错并退出；
		BigInteger h = ecc_bc_spec.getH();
		if (h != null) {
			ECPoint S =  publicKey.multiply(h);//multiply(h);
			if (S.isInfinity())
				throw new IllegalStateException();
		}
		
    	//A4:计算椭圆曲线点[k]Pb=(x2,y2)，将坐标x2,y2的数据类型转换为比特串；
		kpb =  publicKey.multiply(k);//
    	byte[] kpbBytes =  kpb.getEncoded();
    	
    	//A5:计算t=KDF(x2||y2，klen)，若t为全0比特串，则返回A1；
		t = KDF(kpbBytes, klen);
		if(debug)
		{
			System.out.print("t  = ");
			printHexString(t);
		}
	}while(allZero(t));
		
    	//A6:计算C2=M ⊕ t；异或,M明文
    	byte[] C2 = new byte[klen];
		for (int i = 0; i < klen; i++) {
			C2[i] = (byte) (inputBuffer[i] ^ t[i]);
		}
		if(debug)
		{
			System.out.print("C2 = ");
			printHexString(C2);
		}
    	//A7:计算C3=Hash(x2||M||y2);
		byte[] C3 = sm3hash(kpb.getX().toBigInteger().toByteArray(),inputBuffer,
				kpb.getY().toBigInteger().toByteArray());
		if(debug)
		{
			System.out.print("C3 = ");
			printHexString(C3);
		}
    	//A8:输出密文C=C1||C3||C2．
		byte[] encodeResult = new byte[C1Buffer.length + C2.length + C3.length];

		System.arraycopy(C1Buffer, 0, encodeResult, 0, C1Buffer.length);
		System.arraycopy(C2, 0, encodeResult, C1Buffer.length, C2.length);
		System.arraycopy(C3, 0, encodeResult, C1Buffer.length + C2.length, C3.length);
		
		
		return encodeResult;
	}
	
	public String decode(byte[] encodeData, BigInteger privateKey) {
		
		//B1:从C中取出比特串C1，将C1的数据类型转换为椭圆曲线上的点，验证C1是否满足椭圆曲线方程，若不满足则报错并退出；
		byte[] C1Byte= new byte[65];
		System.arraycopy(encodeData, 0, C1Byte, 0, C1Byte.length);
		ECPoint C1;
		if(type.equals("Fp"))
			C1 = curveFp.decodePoint(C1Byte);
		else
			C1 = curveF2m.decodePoint(C1Byte);
		byte[] C1Buffer;
		if(type.equals("Fp"))
			C1Buffer =  C1.getEncoded();
		else
			C1Buffer =  C1.getEncoded();
		if(debug)
		{
			System.out.print("C1 = ");
			printHexString(C1Buffer);
		}
		
		
		//B2:计算椭圆曲线点S=[h]C1，若S是无穷远点，则报错并退出；
		BigInteger h = ecc_bc_spec.getH();
		if (h != null) {
			ECPoint S = C1.multiply(h);
			if (S.isInfinity())
				throw new IllegalStateException();
		}
		
		
		//B3:计算[db]C1=(x2，y2)，将坐标x2，y2的数据类型转换为比特串；
		ECPoint dBC1 = C1.multiply(privateKey);
		byte[] dBC1Bytes = dBC1.getEncoded();
		
		
		//B4:计算t=KDF(x2||y2,klen)，若t为全0比特串，则报错并退出；
		int klen = encodeData.length - 65 - DIGEST_LENGTH;
		byte[] t = KDF(dBC1Bytes, klen);
		if(debug)
		{
			System.out.print("t  = ");
			printHexString(t);
		}
		
		//B5:从C中取出比特串C2，计算M'=C2⊕t；
		byte[] M = new byte[klen];
		byte[] C2 = new byte[30];
		System.arraycopy(encodeData, 65, C2, 0, klen);
		for (int i = 0; i < M.length; i++) {
			M[i] = (byte) ( C2[i]^ t[i]);//encodeData[C1Byte.length + i]
		}
		if(debug)
		{
			System.out.print("C2 = ");
			printHexString(C2);
			System.out.print("M' = ");
			printHexString(M);
		}
		
		
		//B6:计算u=Hash(x2||M'||y2)，从C中取出比特串C3，若u≠C3，则报错并退出；
		byte[] C3 = new byte[DIGEST_LENGTH];
		System.arraycopy(encodeData, encodeData.length - DIGEST_LENGTH, C3, 0, DIGEST_LENGTH);
		byte[] u = sm3hash(dBC1.getX().toBigInteger().toByteArray(), M,
				dBC1.getY().toBigInteger().toByteArray());
		if (Arrays.equals(u, C3)) {
			if (debug)
				System.out.println("解密成功");
			try {
				return new String(M, "UTF8");//B7:输出明文M'
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			return null;
		} else {
			if (debug) {
				System.out.print("u  = ");
				printHexString(u);
				System.out.print("C3 = ");
				printHexString(C3);
				System.err.println("解密验证失败");
			}
			return null;
		}
		
	}
	
	public Signature sign(String M,String ID,SM2KeyPair keyPair) {
		//A1:设置M_=ZA||M；
		byte[] ZA = ZA(ID,keyPair.getPublicKey());
		byte[] M_ = join(ZA, M.getBytes());
		//A2:计算e=Hv(M_)，将e的数据类型转换为整数；
		BigInteger e = new BigInteger(1, sm3hash(M_));
		BigInteger k;
		BigInteger r;
		BigInteger s;
		do {
		do {
		//A3:用随机数发生器产生随机数k∈[1，n一1]
		k = randomgenerator(ecc_bc_spec.getN());
		//A4:计算椭圆曲线点(x1，y1)=[k]G，将x1的数据类型转换为整数
		ECPoint p = G.multiply(k);
		BigInteger x1 = p.getX().toBigInteger();
		//A5:计算r=(e+x1)mod n，若r=0或r+k=n，则返回A3；
		r = e.add(x1).mod(ecc_bc_spec.getN());
		}while(r.equals(BigInteger.ZERO)||r.add(k).equals(ecc_bc_spec.getN()));
		//A6:计算s=((1+dA)^-1·(k一r·dA))mod n，若s=0，则返回A3；
		s = ((keyPair.getPrivateKey().add(BigInteger.ONE).modInverse(ecc_bc_spec.getN()))
				.multiply((k.subtract(r.multiply(keyPair.getPrivateKey()))).mod(ecc_bc_spec.getN()))).mod(ecc_bc_spec.getN());
		}while(s.equals(BigInteger.ZERO));
		//A7:将r，s的数据类型转换为字节串，消息M的签名为(r，s)．
		
		return new Signature(r,s);
	}
	
	public boolean  verify(String M, Signature signature, String IDA, ECPoint PublicKey) {
		//B1．检验r'∈[1，n一1]是否成立，若不成立则验证不通过；
		if (!between(signature.r, BigInteger.ONE, ecc_bc_spec.getN()))
			return false;
		
		//B2．检验s'∈[1，n—1]是否成立，若不成立则验证不通过；
		if (!between(signature.s, BigInteger.ONE, ecc_bc_spec.getN()))
			return false;
		
		//B3．置M'_=ZA||M'；
		byte[] M_ = join(ZA(IDA, PublicKey), M.getBytes());
		
		//B4．计算e'=Hv(M'_)将e'的数据类型转换为整数
		BigInteger e = new BigInteger(1, sm3hash(M_));
		
		//B5．将r'，s'的数据类型转换为整数，计算t=(r'+s')mod n，若t=0，则验证不通过；
		BigInteger t = signature.r.add(signature.s).mod(ecc_bc_spec.getN());
		if (t.equals(BigInteger.ZERO))
			return false;
		
		//B6．计算椭圆曲线点(x1'，y1')=[s']G+[t]PA；
		ECPoint p1 = G.multiply(signature.s);
		ECPoint p2 = PublicKey.multiply(t);
		
		//B7．将x1'的数据类型转换为整数，计算R=(e'+x1')mod n 检验R=r'是否成立．若成立则验证通过；否则验证不通过．
		BigInteger x1 = p1.add(p2).getX().toBigInteger();
		BigInteger R = e.add(x1).mod(ecc_bc_spec.getN());
		if (R.equals(signature.r))
			return true;
		return false;
	}
	
	private static class sendmessage implements Serializable {
		final byte[] R; //R点
		final byte[] S; //验证S
		final byte[] Z; //用户标识
		final byte[] K; //公钥

		public sendmessage(byte[] r, byte[] s,byte[] z,ECPoint pKey) {
			R = r;
			S = s;
			Z=z;
			K=pKey.getEncoded();
		}
	}
	
	public static class KeyExchange {
		BigInteger rA;
		ECPoint RA;
		ECPoint V;
		byte[] Z;
		byte[] key;
		
		String ID;
		SM2KeyPair keyPair;

		public KeyExchange(String ID,SM2KeyPair keyPair) {
			this.ID=ID;
			this.keyPair = keyPair;
			this.Z=ZA(ID, keyPair.getPublicKey());
	}
		public sendmessage KeyExchangeStep1() {
			//A1．用随机数发生器产生随机数rA∈[1，n一1]；
			rA = randomgenerator(ecc_bc_spec.getN());
			//A2．计算椭圆曲线点RA=[rA]G=(x1，y1)；
			RA = G.multiply(rA);
			//A3．将RA发送给用户B；
			return new sendmessage(RA.getEncoded(), null,Z,keyPair.getPublicKey());
		}
		
		public sendmessage KeyExchangeStep2(sendmessage msg) {
			//B1．用随机数发生器产生随机数rB∈[1， n一1]；
			BigInteger rB = randomgenerator(ecc_bc_spec.getN());
			//B2．计算椭圆曲线点RB=[rB]G=(x2，y2)；
			ECPoint RB = G.multiply(rB);
			this.rA=rB;
			this.RA=RB;
			//B3．从RB中取出域元素x2，将x2的数据类型转换为整数，计算x2_=2^w+(x2&(2^w一1))；
			BigInteger x2 = RB.getX().toBigInteger();
			x2 = new BigInteger("2").pow(w).add(x2.and(new BigInteger("2").pow(w).subtract(BigInteger.ONE)));
			//B4. 计算tB=(dB+x2_·rB)mod n；
			BigInteger tB = keyPair.getPrivateKey().add(x2.multiply(rB)).mod(ecc_bc_spec.getN());
			//B5．验证RA是否满足椭圆曲线方程，若不满足则协商失败；否则从RA中取出域元素x1,将x1的数据类型转换为整数，计算x1_=2^w+(x1＆(2^w一1))：
			ECPoint RA ;
			if(type.equals("Fp"))
				RA = curveFp.decodePoint(msg.R);
			else
				RA = curveF2m.decodePoint(msg.R);
			BigInteger x1 = RA.getX().toBigInteger();
			x1 = new BigInteger("2").pow(w).add(x1.and(new BigInteger("2").pow(w).subtract(BigInteger.ONE)));
			//B6．计算椭圆曲线点V=[h·tB](PA+[x1_]RA)=(xv，yv)，若y是无穷远点，则B协商失败；否则将xv,yv的数据类型转换为比特串；
			ECPoint aPublicKey;
			if(type.equals("Fp"))
				aPublicKey=curveFp.decodePoint(msg.K);
			else
				aPublicKey=curveF2m.decodePoint(msg.K);
			ECPoint temp = aPublicKey.add(RA.multiply(x1));
			ECPoint V = temp.multiply(ecc_bc_spec.getH().multiply(tB));
			if(V.isInfinity())
				throw new IllegalStateException();
			this.V = V;
			byte[] xv = V.getX().toBigInteger().toByteArray();
			byte[] yv = V.getY().toBigInteger().toByteArray();
			
			//B7．计算KB=KDF(xv||yv||ZA||ZB,klen)；
			byte[] KB = KDF(join(xv, yv, msg.Z, this.Z), 16);
			//B8．(选项)将RA的坐标x1，y1和RB的坐标x2，y2的数据类型转换为比特串。计算SB=Hash(0x02||yv||Hash(ZA||ZB||x1||y1||x2||y2))；
			key = KB;
			System.out.print("协商得B密钥:");
			printHexString(KB);
			byte[] SB = sm3hash(
							new byte[] { 0x02 }, 
							yv,
							sm3hash(
									xv, 
									msg.Z, 
									this.Z, 
									RA.getX().toBigInteger().toByteArray(),
									RA.getY().toBigInteger().toByteArray(), 
									RB.getX().toBigInteger().toByteArray(),
									RB.getY().toBigInteger().toByteArray()
									)
							);
			//B9．将RB，(选项SB)发送给用户A；
			return new sendmessage(RB.getEncoded(), SB,this.Z,keyPair.getPublicKey());
		}
		
		public sendmessage KeyExchangeStep3(sendmessage msg) {
			//A4．从RA中取出域元素x1，计算x1_=2^w+(x1&(2^w一1))；
			BigInteger x1 = RA.getX().toBigInteger();
			x1 = new BigInteger("2").pow(w).add(x1.and(new BigInteger("2").pow(w).subtract(BigInteger.ONE)));
			//A5．计算tA=(dA+x1_·rA)mod n；
			BigInteger tA = keyPair.getPrivateKey().add(x1.multiply(rA)).mod(ecc_bc_spec.getN());
			//A6．验证RB是否满足椭圆曲线方程，若不满足则协商失败；否则从RB中取出域元素x2，将x2的数据类型转换为整数，计算x2_=2^w+(x2&(2^w一1))；
			ECPoint RB;
			if(type.equals("Fp"))
				RB = curveFp.decodePoint(msg.R);
			else
				RB = curveF2m.decodePoint(msg.R);
			BigInteger x2 = RB.getX().toBigInteger();
			x2 = new BigInteger("2").pow(w).add(x2.and(new BigInteger("2").pow(w).subtract(BigInteger.ONE)));
			//A7．计算椭圆曲线点U=[h·tA](PB+[x2_]RB)=(xU，yU)，若U是无穷远点，则A协商失败；否则将xU,yU的数据类型转换为比特串；
			ECPoint bPublicKey;
			if(type.equals("Fp"))
				bPublicKey = curveFp.decodePoint(msg.K);
			else
				bPublicKey = curveF2m.decodePoint(msg.K);
			ECPoint temp = bPublicKey.add(RB.multiply(x2));
			ECPoint U = temp.multiply(ecc_bc_spec.getH().multiply(tA));
			if (U.isInfinity())
				throw new IllegalStateException();
			this.V=U;
			//A8．计算KA=KDF(xU||yU||ZA||ZB，klen)；
			byte[] xU = U.getX().toBigInteger().toByteArray();
			byte[] yU = U.getY().toBigInteger().toByteArray();
			byte[] KA = KDF(join(xU, yU,
					this.Z, msg.Z), 16);
			System.out.print("协商得A密钥:");
			printHexString(KA);
			//A9．(选项)RA的坐标x1，y1和RB的坐标x2，y2的数据类型转换为比特串，计算S1=Hash(0x02||yU||Hash(xU||ZA||ZB||x1||y1||x2||y2))，
			//并检验S1=SB是否成立，若等式不成立则从B到A的密钥确认失败；
			byte[] s1= sm3hash(
							new byte[] { 0x02 }, 
							yU,
							sm3hash(
									xU, 
									this.Z, 
									msg.Z, 
									RA.getX().toBigInteger().toByteArray(),
									RA.getY().toBigInteger().toByteArray(), 
									RB.getX().toBigInteger().toByteArray(),
									RB.getY().toBigInteger().toByteArray()
									)
							);
			if(Arrays.equals(msg.S, s1))
				System.out.println("B->A 密钥确认成功");
			else
				System.out.println("B->A 密钥确认失败");
			//A10．(选项)计算SA=Hash(0x03||yU||Hash(xU||ZA||ZB||x1||y1||x2||y2))，并将SA发送给用户B．
			byte[] sA= sm3hash(
							new byte[] { 0x03 },
							yU,
							sm3hash(
									xU,
									this.Z, //ZA
									msg.Z,  //ZB
									RA.getX().toBigInteger().toByteArray(), //x1
									RA.getY().toBigInteger().toByteArray(), //y1
									RB.getX().toBigInteger().toByteArray(), //x2
									RB.getY().toBigInteger().toByteArray()  //y2
									)
							);
			
			return new sendmessage(RA.getEncoded(), sA,this.Z,keyPair.getPublicKey());
		}
	
		public void KeyExchangeStep4(sendmessage msg) {
			//B10．(选项)计算S2=Hash(0X03||yv||Hash(xv||ZA||ZB||x1||y1||x2||y2))，并检验S2=SA是否成立，若等式不成立则从A到B的密钥确认失败．
			byte[] xV = V.getX().toBigInteger().toByteArray();
			byte[] yV = V.getY().toBigInteger().toByteArray();
			ECPoint RA;
			if(type.equals("Fp"))
				RA = curveFp.decodePoint(msg.R);
			else
				RA = curveF2m.decodePoint(msg.R);
			byte[] s2= sm3hash(new byte[] { 0x03 }, yV,
					sm3hash(xV, msg.Z, this.Z, RA.getX().toBigInteger().toByteArray(),
							RA.getY().toBigInteger().toByteArray(), this.RA.getX().toBigInteger().toByteArray(),
							this.RA.getY().toBigInteger().toByteArray()));
			if(Arrays.equals(msg.S, s2))
				System.out.println("A->B 密钥确认成功");
			else
				System.out.println("A->B 密钥确认失败");
		}
	}
	public static void main(String[] args) throws UnsupportedEncodingException {
		
		System.out.println("-----------------密钥生成-----------------");
		 // 用户自己主私钥,用户自己设置
		Scanner sc = new Scanner(System.in); 
		do{
			System.out.println("请输入椭圆曲线类型（Fp或F2m）："); 
			type = sc.nextLine();
		}
	    while(!type.equals("Fp") && !type.equals("F2m"));	
		System.out.println("椭圆曲线类型设置为"+type);
		SM2 sm2 = new SM2();
		SM2KeyPair keyPair = sm2.generateKeyPair();
		ECPoint publicKey = keyPair.getPublicKey();
		BigInteger privateKey = keyPair.getPrivateKey();
	
		System.out.println("privateKey = " + privateKey);
		System.out.println("publicKey = " + publicKey);
		System.out.println("-----------------公钥加密-----------------");
		
		byte[] data = sm2.encode("测试加密aaaaaaaaaaa123aabb", publicKey);
		System.out.println("明文 = " + data);
		System.out.print("密文 = ");
		SM2.printHexString(data);
		System.out.println("-----------------私钥解密-----------------");
		System.out.println("解密后明文:" + sm2.decode(data, privateKey));
	
		System.out.println("-----------------数字签名-----------------");
		String IDA = "Ramperlogic";
		String M = "要签名的信息";
		Signature signature = sm2.sign(M, IDA, new SM2KeyPair(publicKey, privateKey));
		System.out.println("用户标识:" + IDA);
		System.out.println("签名信息:" + M);
		System.out.println("数字签名:" + signature);
		System.out.println("验证签名:" + sm2.verify(M, signature, IDA, publicKey));
		
		System.out.println("-----------------密钥交换-----------------");
		String aID = "Alice";
		SM2KeyPair aKeyPair = sm2.generateKeyPair();
		KeyExchange aKeyExchange = new KeyExchange(aID,aKeyPair);
		System.out.println("AID:" + aID);
		System.out.println("AKeyPair:" + aKeyPair);
		System.out.println("AKeyExchange:" + aKeyExchange);
		System.out.println();
		
		String bID = "Bob";
		SM2KeyPair bKeyPair = sm2.generateKeyPair();
		KeyExchange bKeyExchange = new KeyExchange(bID,bKeyPair);
		System.out.println("BID:" + bID);
		System.out.println("BKeyPair:" + bKeyPair);
		System.out.println("BKeyExchange:" + bKeyExchange);
		System.out.println();
		
		sendmessage msg1 = aKeyExchange.KeyExchangeStep1();		//RA
		sendmessage msg2 = bKeyExchange.KeyExchangeStep2(msg1);	//RB
		sendmessage msg3 = aKeyExchange.KeyExchangeStep3(msg2);	//SA
		bKeyExchange.KeyExchangeStep4(msg3);					//S2=SA->success

	}
}

