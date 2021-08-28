package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter2;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

/**
 * Spring Security Login Process
 * 1. 사용자가 id, password 입력 후 로그인 시도.
 * 2. AuthenticationFilter -> UsernamePasswordAuthenticationToken 생성 후 AuthenticationManager 전달한다.
 * 3. AuthenticationManager(는) 등록된 AuthenticationProvider(들)을 조회하여 사용자 정보 인증을 요구한다.
 * 4. AuthenticationProvider(는) UserDetailsService(PrincipalDetailsService)를 통해서 입력받은 사용자 정보(username,email..)를
 *    User Database 조회하여 사용자정보를 UserDetails(PrincipalDetails) VO에 생성 및 사용자 정보를 이용하여 입력된 id, password 비교 후
 *    사용자 인증에 성공한 경우 UsernameAuthenticationToken 생성 후 AuthenticationManager 반환한다.
 * 5. AuthenticationManager(는) UsernameAuthenticationToken(을) AuthenticationFilter(에게) 전달한다.
 * 6. AuthenticationFilter(는) 전달받은 UsernameAuthenticationToken(을) LoginSuccessHandler(로) 전송하고 SecurityContextHolder(에) 저장한다.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.csrf()
                .disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .addFilter(corsFilter)
            .formLogin()
                .disable()
            .httpBasic()
                .disable()
            // JwtAuthenticationFilter Filter 적용.
            .addFilter(new JwtAuthenticationFilter(authenticationManager()))   //AuthenticationManager
            // JwtAuthorizationFilter Filter 적용
            .addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository))
            .authorizeRequests()
            .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
            .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
            .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
            .anyRequest()
                .permitAll()

        ;
    }
}
