package com.ssr.springbootjwt.web.conf.resolver;

import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import com.ssr.springbootjwt.web.security.authentication.CurrentAccount;
import com.ssr.springbootjwt.web.security.token.AccessToken;

import jakarta.servlet.http.HttpServletRequest;

public class CurrentAccountResolver implements HandlerMethodArgumentResolver {

    private final AccessToken accessToken;

    public CurrentAccountResolver(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return CurrentAccount.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter, @Nullable ModelAndViewContainer mavContainer,
            NativeWebRequest webRequest, @Nullable WebDataBinderFactory binderFactory) throws Exception {
        // jwt already verified in JwtAuthorizationManager
        var request = (HttpServletRequest) webRequest.getNativeRequest();
        var jwt = accessToken.get(request);
        return accessToken.getCurrentAccount(jwt);
    }

}
