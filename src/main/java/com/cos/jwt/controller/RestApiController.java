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

    /**
     * Path. Http://localhost:8080/home
     * @return String
     */
    @GetMapping(value = {"/home"})
    public String home(){
        return "<h1>Home Init</h1>";
    }

    /**
     * Path. Http://localhost:8080/token
     * @return String
     */
    @PostMapping(value = {"/token"})
    public String token(){
        return "<h1>token</h1>";
    }

    /**
     * 회원가입
     * Path. Http://localhost:8080/join
     * @param user @RequestBody User Class
     * @return String
     */
    @PostMapping(value = "/join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    /**
     * Path. Http://localhost:8080/api/v1/user
     * Spring Security Filter JwtAuthorizationFilter extends BasicAuthenticationFilter
     * 사용자의 토큰을 검증 후 /api/v1/user 경로에 접근가능한지 테스트한다.
     *  - ROLE_USER(o), ROLE_MANAGER(o), ROLE_ADMIN(o)
     * @return String
     */
    @GetMapping(value = "/api/v1/user")
    public String userToken(){
        return "userToken";
    }

    /**
     * Path. Http://localhost:8080/api/v1/manager
     * Spring Security Filter JwtAuthorizationFilter extends BasicAuthenticationFilter
     * 사용자의 토큰을 검증 후 /api/v1/manager 경로에 접근가능한지 테스트한다.
     *  - ROLE_USER(x), ROLE_MANAGER(o), ROLE_ADMIN(o)
     * @return String
     */
    @GetMapping(value = "/api/v1/manager")
    public String managerToken(){
        return "managerToken";
    }

    /**
     * Path. Http://localhost:8080/api/v1/admin
     * Spring Security Filter JwtAuthorizationFilter extends BasicAuthenticationFilter
     * 사용자의 토큰을 검증 후 /api/v1/admin 경로에 접근가능한지 테스트한다.
     *  - ROLE_USER(x), ROLE_MANAGER(x), ROLE_ADMIN(o)
     * @return String
     */
    @GetMapping(value = "/api/v1/admin")
    public String adminToken(){
        return "adminToken";
    }


}
