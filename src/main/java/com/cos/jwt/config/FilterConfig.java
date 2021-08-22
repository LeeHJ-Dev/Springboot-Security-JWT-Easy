package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Filter Configuration File.
 *  - FilterRegistrationBean Class 이용해서 Filter1 or Filter2 등록한다.
 */
@Configuration
public class FilterConfig {

    /**
     * Filter1(을) FilterRegistrationBean 등록한다.
     *  - Url Pattern("/*")
     *  - 즉, 모든 경로에서 유입되는 경우 해당 필터를 적용한다.
     * @return FilterRegistrationBean bean(Filter1)
     */
    @Bean
    public FilterRegistrationBean<MyFilter1> filter1(){
        System.out.println("FilterConfig.filter1 - start ");
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*");
        bean.setOrder(0); //낮은 번호가 필터중에서 가장 먼저 실행됨
        return bean;
    }

    /**
     * Filter2(을) FilterRegistrationBean 등록한다.
     *  - Url Pattern("/*")
     *  - 즉, 모든 경로에서 유입되는 경우 해당 필터를 적용한다.
     * @return FilterRegistrationBean bean(Filter2)
     */
    @Bean
    public FilterRegistrationBean<MyFilter2> filter2(){
        System.out.println("FilterConfig.filter2 - start ");
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        bean.addUrlPatterns("/*");
        bean.setOrder(1);
        return bean;
    }


}
