package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.config.auth.PrincipalDetailsService;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

/**
 * 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 있음
 * 1. /login 요청해서 username, password Post 전송
 * 2 UsernamePasswordAuthenticationFilter 동작을 함
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter.attemptAuthentication - start ");

        //1. username, password
        try {
            //System.out.println("request.getInputStream() = " + request.getInputStream().toString());
            /*
            BufferedReader br = request.getReader();
            String input = null;
            while((input = br.readLine())!= null){
                System.out.println("input = " + input);
            }
            */

            System.out.println("request.getInputStream() = " + request.getInputStream());

            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("user = " + user);


            //토큰생성
            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());

            //PrincipalDetailsService의 loadUserByUsername() 함수가 실행된다.
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            //authentication 객체가 session 영역에 저장됨 => 로그인 되었다는 것.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인완료됨 : principalDetails = " + principalDetails.getUser().getUsername());

            /**
             * authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면됨
             * 리턴의 이유는 권한 관리를 security 가 대신 해주기 때문에 편하려고 하는것임.
             * 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리때문에 session 넣어준다.
             */
            return authentication;  //세션에 저장한다.

        } catch (IOException e) {
            e.printStackTrace();
        }


        //2. 정상인지 로그인 시도를 해본다.
        //2-1) autnenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출된다.


        //3. PrincipalDetails 세션에 담고(권한체크)

        //4. JWT 토큰을 만들어서 응답해주면된다.
        return null;
    }

    /**
     * 위 함수 attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행된다.
     * JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 reponse 해주면 됨.
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("JwtAuthenticationFilter.successfulAuthentication 인증이 완료되었다는 뜻임. ");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        System.out.println("인증완료 후 principalDetails 값 = " + principalDetails);

        //jwt 생성
        //RSA 방식은 아니고 Hash 암호방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        //헤더에 토큰 셋팅
        response.addHeader("Authorization", "Bearer " + jwtToken);
        System.out.println("jwtToken = " + jwtToken);

        //super.successfulAuthentication(request, response, chain, authResult);
    }
}
