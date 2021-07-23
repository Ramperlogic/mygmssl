package com.ypy.mygmssl.util;

import com.ypy.mygmssl.service.sm2.impl.SM2ServiceImpl;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

public class SM2Factory {
    private static final int DIGEST_LENGTH = 32;
    private static int C1lenth;
    /*
     * ECCurve.Fp
     *	public ECCurve.Fp(java.math.BigInteger q,
     *            java.math.BigInteger a,
     *            java.math.BigInteger b)
     */

    private static ECCurve.F2m curveF2m;
    private static String type = "Fp";
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
    private static BigInteger aF2m = new BigInteger("0");
    private static BigInteger bF2m = new BigInteger("00"+
            "E78BCD09"+"746C2023"+"78A7E72B"+"12BCE002"+"66B9627E"+"CB0B5A25"+"367AD1AD"+"4CC6242B", 16);
    private static BigInteger gxF2m = new BigInteger("00"+
            "CDB9CA7F"+"1E6B0441"+"F658343F"+"4B10297C"+"0EF9B649"+"1082400A"+"62E7A748"+"5735FADD", 16);
    private static BigInteger gyF2m = new BigInteger("01"+
            "3DE74DA6"+"5951C4D7"+"6DC89220"+"D5F7777A"+"611B1C38"+"BAE260B1"+"75951DC8"+"060C2B3E", 16);
    private static int m = 257;
    private static int k = 12;
    private static ECCurve.Fp curveFp= new ECCurve.Fp(pFp, // q
            aFp, // a
            bFp);
    private static ECPoint G = curveFp.createPoint(gxFp, gyFp ,false);
    private static ECDomainParameters ecc_bc_spec = new ECDomainParameters(curveFp, G, nFp);

    private static final Logger logger = LoggerFactory.getLogger(SM2Factory.class);

    public SM2Factory() {
        /*
		curveFp = new ECCurve.Fp(pFp, // q
				aFp, // a
				bFp); // b

		curveF2m = new ECCurve.F2m(m, k, aF2m, bF2m);
		if(type.equals("Fp"))
		{
			G = curveFp.createPoint(gxFp, gyFp ,false);
			ecc_bc_spec = new ECDomainParameters(curveFp, G, nFp);
			if(debug)
			{
				System.out.println("G = "+G.toString());
				System.out.println("ecc_bc_spec = "+ecc_bc_spec.toString());
			}
		}
		else
		{
			G = curveF2m.createPoint(gxF2m, gyF2m, false);
			ecc_bc_spec = new ECDomainParameters(curveF2m, G, nF2m);
			if(debug)
			{
				System.out.println("G = "+G.toString());
				System.out.println("ecc_bc_spec = "+ecc_bc_spec.toString());
			}
		}
    */
    }


    public ECDomainParameters ecc_bc_spec(){
        return ecc_bc_spec;
    }

    public ECPoint G (){
        return G;
    }

    public static boolean checkPublicKeyFp(ECPoint publicKey) {
        //Fp方法：
        //验证P不是无穷远点
        if (!publicKey.isInfinity()) {

            BigInteger x = publicKey.getX().toBigInteger();
            BigInteger y = publicKey.getY().toBigInteger();
            logger.info("x = {}",x);
            logger.info("y = {}",y);

            //验证公钥P的坐标xP和yP是域Fp中的元素(即验证xP和yP是区间[0; p−1]中的整数)
            if (between(x, new BigInteger("0"), pFp) && between(y, new BigInteger("0"), pFp)) {

                BigInteger xResult = x.pow(3).add(aFp.multiply(x)).add(bFp).mod(pFp);
                //验证yP^2≡xP^3+axP+b mod P
                logger.info("xResult: {}",xResult.toString());

                BigInteger yResult = y.pow(2).mod(pFp);

                logger.info("yResult: {}",yResult.toString());

                if (yResult.equals(xResult) && publicKey.multiply(nFp).isInfinity()) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean checkPublicKeyF2m(ECPoint publicKey) {
        //F2m方法
        //验证P不是无穷远
        if(!publicKey.isInfinity()) {

            BigInteger x = publicKey.getX().toBigInteger();
            BigInteger y = publicKey.getY().toBigInteger();
            logger.info("x = {}",x);
            logger.info("y = {}",y);
            logger.info("m = {}",m);
            logger.info("xlen = {}",publicKey.getX().getFieldSize());
            logger.info("ylen = {}",publicKey.getY().getFieldSize());

            //验证公钥P的坐标xP和yP是域F2m中的元素(即验证xP和yP是长度为m的比特串)
            if (publicKey.getX().getFieldSize()==m && publicKey.getY().getFieldSize()==m)
            {
                //在F2m中验证yP^2+xPyP=xP^3+axP^2+b
                BigInteger xResult = y.pow(2).add(x.multiply(y));
                BigInteger yResult = x.pow(3).add(aF2m.multiply(x.pow(2))).add(bF2m);
                logger.info("xResult = {}",xResult);
                logger.info("yResult = {}",yResult);

                if(xResult.equals(yResult))//验证[n]P=O
                {
                    if (publicKey.multiply(nF2m).isInfinity())
                    {
                        return true;
                    }
                }
            }

        }
        return true;
    }

    private static boolean between(BigInteger param, BigInteger min, BigInteger max) {
        if (param.compareTo(min) >= 0 && param.compareTo(max) < 0) {
            return true;
        } else {
            return false;
        }
    }
}
