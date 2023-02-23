package com.rfos.springsecurityjjwtredis.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author rfos
 * @Date 2022/11/8 20:09
 * @Description TODO 管理控制类
 */
@RestController
public class UserController {
    /**
     * 成功访问
     */
    @GetMapping("/admin/success")
    public String  success(){
        return "success!";
    }
    /**
     * 失败访问
     */
    @GetMapping("/user/failed")
    public String  failed(){
        return "failed!";
    }
}
