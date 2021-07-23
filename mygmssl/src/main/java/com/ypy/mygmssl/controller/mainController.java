package com.ypy.mygmssl.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class mainController {

    private final Logger logger = LoggerFactory.getLogger(mainController.class);

    @RequestMapping("/")
    public String toMain(){
        logger.info("主页登录成功");
        return "main";
    }

}
