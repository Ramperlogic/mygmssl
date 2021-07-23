package com.ypy.mygmssl.controller;

import com.ypy.mygmssl.pojo.sm2.SM2KeyPair;
import com.ypy.mygmssl.service.sm2.SM2Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/SM2")
public class sm2Controller {

    private final Logger logger;

    @Autowired(required=false)
    private SM2Service sm2Service;

    public sm2Controller() {
        logger = LoggerFactory.getLogger(sm2Controller.class);
    }

    @RequestMapping("/SM2/generateKeyPair")
    public SM2KeyPair generateKeyPair() {
        return sm2Service.generateKeyPair();
    }


}
