package com.cos.jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RestApiController {

    @GetMapping(value = {"/home"})
    public String home(){
        return "<h1>Home Init</h1>";
    }

    @PostMapping(value = {"/token"})
    public String token(){
        return "<h1>token</h1>";
    }


}
