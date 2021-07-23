package com.ypy.mygmssl.pojo.sm2;

import com.ypy.mygmssl.util.HexUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;


public class SM2KeyPair {

    private final ECPoint publicKey;
    private final BigInteger privateKey;

    public SM2KeyPair(ECPoint publicKey, BigInteger privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }
    public ECPoint getPublicKey() {
        return publicKey;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    @Override
    public String toString() {
        return HexUtils.bytes2Hex(publicKey.getEncoded()) + "," + privateKey.toString(16);
    }

    public String getpublicKey() {
        return HexUtils.bytes2Hex(publicKey.getEncoded());
    }

    public String getprivateKey() {
        return privateKey.toString(16);
    }
}
