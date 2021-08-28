package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Path. Http://localhost:8080/login -> Spring Security Call
 *
 * UserDetailsService Interface.
 *
 *
 */

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * 사용자의 정보(username, email)를 이용하여 Database User 정보 조회 후 PrincipalDetails extends UserDetails return
     * @param username
     * @return PrincipalDetails extends UserDetails 사용자정보
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService.loadUserByUsername Start ");
        User userEntity = userRepository.findByUsername(username);
        System.out.println("userEntity = " + userEntity);
        System.out.println("PrincipalDetailsService.loadUserByUsername End");
        return new PrincipalDetails(userEntity);
    }
}
