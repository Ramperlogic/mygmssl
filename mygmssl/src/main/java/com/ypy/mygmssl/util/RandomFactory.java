package com.ypy.mygmssl.util;

import java.math.BigInteger;
import java.util.Random;


public class RandomFactory {

    /**
     * 随机数发生器
     */
    public static BigInteger Randomgenerator(BigInteger max) {
        Random random = new Random();
        BigInteger r = new BigInteger(256,random);

        while(r.compareTo(max) >= 0) {
            r = new BigInteger(128,random);
        }
        return r;
    }
}
