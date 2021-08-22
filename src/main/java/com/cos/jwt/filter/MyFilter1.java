package com.cos.jwt.filter;

import javax.servlet.*;
import java.io.IOException;

/**
 * Class Name : Filter (interface)
 *  1. 필터(Filter)
 *   - 필터의 가능 큰 역할은 사용자의 요청을 검증하고 필요에 따라 데이터를 추가하거나 변조하는 것이라고 보면 될거 같다. 예를 들면 인코딩 필터는
 *   사용자가 요청한 내용을 담은 request 객체의 정보를 특정 인코딩 타입으로 중간에 변경해준다. Filter 는 FilterChain(필터체인)을 통해서
 *   여러 필터가 연쇄적으로 동작할게 할 수 있습니다.
 *   - Request -> Filter1 -> Filter2 -> Filter3 -> Resource
 *   - 필터는 주로 요청에 대한 인증, 권한 체크 등을 하는데 사용된다. 구체적으로 들어온 요청이 DispatcherServlet 전달되기 전 헤더를 검사해
 *   인증 토큰이 없는지 혹은 있는지.. 있다면 올바른 토큰으로 구성되어 있는것인지.. 검사할 수 있다.
 *   - 필터 클래스를 만들면 Spring Bean(으로) 등록해야한다.
 *   -  Client -> Http Request -> Filter -> DispatcherServlet -> HandlerMapping -> HandlerInterceptor -> Handler(Controller)
 *      -> Business Logic -> View or ViewResolover -> DispatcherServlet -> Filter -> Http Response -> Client
 */
public class MyFilter1 implements Filter {

    /**
     * 필터가 생성될 때 수행되는 메서드.
     * @param filterConfig
     * @throws ServletException
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    /**
     * 클라이언트로부터 Request, Response 가 필터를 거칠 때 수행되는 메서드
     * @param servletRequest
     * @param servletResponse
     * @param filterChain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        System.out.println("MyFilter1 doFilter");
        filterChain.doFilter(servletRequest, servletResponse);
    }

    /**
     * 필터가 소멸될 때 수행되는 메서드
     */
    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
