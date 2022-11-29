package com.ssr.springbootjwt.web.security.authorization;

import java.util.function.Supplier;
import java.util.logging.Logger;
import org.springframework.lang.Nullable;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import com.ssr.springbootjwt.web.security.token.AccessToken;

public class JwtAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final AccessToken accessToken;

    public JwtAuthorizationManager(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    @Nullable
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        return new AuthorizationDecision(accessToken.isExists(object.getRequest()));
    }

}
