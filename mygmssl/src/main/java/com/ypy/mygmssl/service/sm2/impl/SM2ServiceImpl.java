package com.ypy.mygmssl.service.sm2.impl;

import com.ypy.mygmssl.pojo.sm2.SM2KeyPair;
import com.ypy.mygmssl.util.SM2Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;

import static com.ypy.mygmssl.util.RandomFactory.Randomgenerator;
import static com.ypy.mygmssl.util.SM2Factory.checkPublicKeyFp;

@Service
public class SM2ServiceImpl {

    private static final Logger logger = LoggerFactory.getLogger(SM2ServiceImpl.class);

    /**
     * SM2密钥对生成
     */
   // @Override
    public SM2KeyPair generateKeyPair() {
        SM2Factory SM2 = new SM2Factory();
        BigInteger d = Randomgenerator(SM2.ecc_bc_spec().getN().subtract(new BigInteger("1")));

        SM2KeyPair keyPair = new SM2KeyPair(SM2.G().multiply(d), d);//推测F2m在此处出了问题，生成的密钥对的publicKey中X，Y值不在F2m曲线上
        //if(type.equals("Fp"))
       // {
            if (checkPublicKeyFp(keyPair.getPublicKey())) {
                logger.info("密钥对生成成功！");
                return keyPair;
            } else {
                logger.info("密钥对生成失败");
                return null;
            }
        // }
        //else
        /*{
            if (checkPublicKeyF2m(keyPair.getPublicKey())) {
                if (debug)
                    System.out.println("密钥对生成成功！");
                return keyPair;
            } else {
                System.err.println("密钥对生成失败");
                return null;
            }
        */


    }
}
