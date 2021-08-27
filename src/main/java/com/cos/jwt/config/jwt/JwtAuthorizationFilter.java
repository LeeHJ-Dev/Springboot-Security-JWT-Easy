package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 1. 시큐리티가 filter 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있음.
 * 2. 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어 있음
 * 3. 만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 안타요.
 *
 * 1. Spring Security Filter Chain(에서) 요청하는 주소에 인증이 필요한 경우 BasicAuthenticationFilter Filter Class Call.
 *  - 권한이나 인증이 필요한 특정 주소를 사용자가 요청했을 경우 BasicAuthenticationFilter 호출한다.
 *  - JwtAuthorizationFilter extends BasicAuthenticationFilter
 *  - doFilterInternal() Method Call.
 *
 * 2. Spring Security Config AddFilter
 *   ex. addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository))
 *
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    /**
     * 사용자의 자원요청이 인증이 필요한 경우 doFilterInternal() 함수가 호출되며, 헤더의 정보를 이용해서 토큰의 정보(유효성)를 검증한다.
     * @param request
     * @param response
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소가 요청된 경우 ");


        //Http Header : Authorization
        /**
         * 사용자의 요청정보 중 Http Header 데이터 중 "Authorization"의 토큰정보를 읽어온다.
         */
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader = " + jwtHeader);

        /**
         * 토큰의 유효성을 체크한다.
         */
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            //헤더의 토큰정보가 검증이 되지 않았을경우
            chain.doFilter(request,response);
            return ;
        }

        System.out.println("=======================================================");

        /**
         * Http Header JWT 검증을 통해서
         * 1. 헤더의 토큰정보(Authorization) 중 "Bearer "을 공백으로 대체하여 토큰을 조회해온다.
         * 2. JWT.require(알고리즘.HMAC512("cos"))
         * 3. 토큰의 사용자 정보를 파싱해서 정보를 조회한다.
         */
        //JWT 토큰 검증을 해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        String username = JWT.require(Algorithm.HMAC512("cos"))
                .build()
                .verify(jwtToken)
                .getClaim("username")
                .asString();


        System.out.println("username = " + username);
        /**
         * 토큰을 파싱하여 사용자의 정보(username)정보가 있을경우 DB 사용자 정보를 조회하며, 사용자가 있을경우
         * 사용자의 정보(principalDetails, 암호, 권한)을 이용하여 UsernamePasswordAuthenticationToken 생성한다.
         *  => Authentication authentication 정보를 이용해서 SessionContextHolder 사용자 인증정보를 갱신한다.
         */
        if(username != null){
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            //JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        /**
         * Filer Chain 진행.
         */
        chain.doFilter(request,response);
    }
}
