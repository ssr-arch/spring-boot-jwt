package com.ssr.springbootjwt.web.conf;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.ssr.springbootjwt.web.conf.resolver.CurrentAccountResolver;
import com.ssr.springbootjwt.web.security.authentication.AccessToken;

@EnableWebMvc
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final AccessToken accessToken;

    public WebConfig(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new CurrentAccountResolver(accessToken));
    }

}
