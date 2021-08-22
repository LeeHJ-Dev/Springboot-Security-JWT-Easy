package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Path. Http://localhost:8080/login -> Spring Security Call
 */

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService.loadUserByUsername Start ");

        //회원조건체크
        if(username == null){
        }

        //회원검색
        User userEntity = userRepository.findByUsername(username);
        System.out.println("userEntity = " + userEntity);
        if(userEntity == null){
            //에러
        }

        System.out.println("PrincipalDetailsService.loadUserByUsername End");
        return new PrincipalDetails(userEntity);
    }
}