package com.ypy.mygmssl.service.sm2;

import com.ypy.mygmssl.pojo.sm2.SM2KeyPair;

public interface SM2Service {

    /**
     * 生成SM2密钥对
     *
     * @return SM2KeyPair
     */
    SM2KeyPair generateKeyPair();
}
