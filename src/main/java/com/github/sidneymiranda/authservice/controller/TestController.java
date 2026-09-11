package com.github.sidneymiranda.authservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping("/user")
    public String test() {
        return "User endpoint is working!";
    }

    @GetMapping("/admin")
    public String testAdmin() {
        return "Admin endpoint is working!";
    }
}
