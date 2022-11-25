package com.ssr.springbootjwt.web.security.authorization;

import java.util.function.Supplier;
import java.util.logging.Logger;

import org.springframework.lang.Nullable;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.ssr.springbootjwt.web.security.authentication.AccessToken;

public class JwtAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private Logger logger = Logger.getLogger(JwtAuthorizationManager.class.getName());
    private final AccessToken accessToken;

    public JwtAuthorizationManager(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    @Nullable
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        var jwt = accessToken.get(object.getRequest());
        if (jwt == null) {
            logger.severe("access token not found");
            return new AuthorizationDecision(false);
        }
        try {
            accessToken.verify(jwt);
            logger.info("authorization success");
            return new AuthorizationDecision(true);
        } catch (JWTVerificationException e) {
            logger.severe(e.getMessage());
            return new AuthorizationDecision(false);
        }
    }

}
