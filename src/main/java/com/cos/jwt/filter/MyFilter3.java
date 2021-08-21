package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        System.out.println("MyFilter3 doFilter");

        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        req.setCharacterEncoding("UTF-8");

        if(req.getMethod().equals("POST")){
            String headAuth = req.getHeader("Authorization");
            System.out.println("headAuth = " + headAuth);

            if(headAuth.equals("cos")){
                filterChain.doFilter(req, res);
            }else{
                PrintWriter printWriter = res.getWriter();
                printWriter.print("인증안됨!!!!!!");
            }
        }


    }
}
