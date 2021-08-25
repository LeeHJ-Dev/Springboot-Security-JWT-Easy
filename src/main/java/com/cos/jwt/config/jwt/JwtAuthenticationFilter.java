package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
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
import java.io.IOException;
import java.util.Date;

/**
 * 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 있음
 * 1. /login 요청해서 username, password Post 전송
 * 2 UsernamePasswordAuthenticationFilter 동작을 함
 *
 *
 * - UsernamePasswordAuthenticationFilter Class 인증처리 담당 클래스
 * 1. 사용자가 로그인을 진행하는 경우 UsernamePasswordAuthenticationFilter 기능을 대신하는 커스텀 클래스를 사용해서 필터를 추가한다.
 *  ex. JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter
 * 2. 인증 성공 실패에 따라 AuthenticationSuccessHandler or AuthenticationFailureHandler Handler 최종적으로 호출한다.
 * 3. 인증이 성공적으로 진행했다면 리턴값으로 UsernamePasswordAuthenticationToken(을) 세션에 저장한다.
 * 4. SecurityConfig extends WebSecurityConfigurerAdapter
 *  - addFilter(new JwtAuthenticationFilter(authenticationManager())
 *
 *
 *
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수

    /**
     * UsernamePasswordAuthenticationFilter Class Method attemptAuthentication(request, response) 인자값으로 사용자의 username, password
     * 정보를 얻어와서 해당 값을 이용해서 UsernamePasswordAuthenticationToken()을 생성한다. AuthenticationManager(에게) 인증을 진행하도록 위힘한다.
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter.attemptAuthentication - start ");


        ObjectMapper objectMapper = new ObjectMapper();
        try {
            /**
             * HttpRequest Data InputStream() -> User.class Mapping
             * return User class.
             */
            User user = objectMapper.readValue(request.getInputStream(), User.class);

            /**
             * 사용자 토큰생성
             */
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            /**
             * AuthenticationManager Call.
             * - PrincipalDetailsService loadUserByUsername Method call (사용자인증확인)
             * - PrincipalDetails User class return
             * - Authentication Class
             *   ex. PrincipalDetails principalDetails = (PrincipalDetails)authenticate.getPrincipal();
             */
            Authentication authenticate = authenticationManager.authenticate(authenticationToken);

            /**
             * Authentication authenticate.getPrincipal() Method 이용해서 사용자정보 캐스팅 가능
             */
            PrincipalDetails principal = (PrincipalDetails) authenticate.getPrincipal();

            /**
             * return authentication 객체를 리턴하면 SpringSecurity Session 영역에 저장한다.
             * Session 저장하면 SpringSecurity 사용자의 권한관리를 진행하기 때문에 리턴한다.
             * JWT 토큰인 경우 세션을 만들이유는 없지만, 세션처리를 위해서는 Session 리턴한다.
             */
            return authenticate;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * attemptAuthentication 실행 후 인증이 정상적으로 진행되면 successfulAuthentication Method Call.
     *
     *
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

        /**
         * Authentication authResult Parameter Value. User Authentication PrincipalDetails Class.
         */
        System.out.println("JwtAuthenticationFilter.successfulAuthentication 인증이 완료되었다는 뜻임. ");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        System.out.println("인증완료 후 principalDetails 값 = " + principalDetails);

        //jwt 생성
        //RSA 방식은 아니고 Hash 암호방식
        /**
         * Json Web Token Create.
         *  - withSubject() :
         *  - withExpiresAt() :
         *  - withClaim()
         *  - sign()
         *
         * 회원인증용 JWT.
         *  - JWT(을) 사용하는 가장 흔한 시나리오.
         *  - 사용자가 인증을 진행 후 인증이 완료되면(성공하면) 서버는 유저의 정보(PrincipalDetails)에 기반한 토큰을 생성(발급)하여 유저에게 헤더를 통해서 제공한다.
         *    사용자는 서버를 통해서 받은 토큰정보를 이용해서 서버에 JWT(토큰)을 포함해서 전달하면 서버는 클라이언트 요청을 받을때마다 토큰이 유효하고 인증됐는지 검증하고
         *    유저가 요청한 작업에 대한 권한이 있는지 확인하여 요청을 처리한다.
         *  - 서버는 사용자(유저)의 세션을 유지 할 필요가 없으지며 즉, 유저가 로그인되어 있는지 안되어 있는지 신경 쓸 필요가 없어지며, 사용자(유저)가 요청을 했을 때 토큰만
         *    확인하면 되니, 세션관리가 필요없어서 서버의 자원을 많이 아낄 수 있다.
         *
         * 정보 교류 JWT
         *  - JWT(는) 두 개체(Client <-> Server) 사이에서 안정성있게 정보를 교환하기에 좋은 방법이다. 정보가 sign 되어 있기 때문에 정보를 보낸이가 바뀌지 않았는지
         *    정보가 도중에 조작되지는 않았는지 검증할 수 있다.
         *  - 웹서버의 경우 Http 헤더에 넣어서 전달 할 수도 있고, URL(의) 파라미터로 전달 할 수도 있습니다.
         *
         */
        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        /**
         * Http Response Header Token Setting
         * Header(Key:Value) : ("Authorization" : "Bearer " + TokenValue)
         */
        response.addHeader("Authorization", "Bearer " + jwtToken);
        System.out.println("jwtToken = " + jwtToken);

        //super.successfulAuthentication(request, response, chain, authResult);
    }
}









