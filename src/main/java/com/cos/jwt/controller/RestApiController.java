package com.cos.jwt.controller;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping(value = {"/home"})
    public String home(){
        return "<h1>Home Init</h1>";
    }

    @PostMapping(value = {"/token"})
    public String token(){
        return "<h1>token</h1>";
    }

    @PostMapping(value = "/join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    @GetMapping(value = "/api/v1/user")
    public String userToken(){
        return "userToken";
    }
    @GetMapping(value = "/api/v1/manager")
    public String managerToken(){
        return "managerToken";
    }
    @GetMapping(value = "/api/v1/admin")
    public String adminToken(){
        return "adminToken";
    }


}
