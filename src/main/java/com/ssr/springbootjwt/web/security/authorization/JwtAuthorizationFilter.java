package com.ssr.springbootjwt.web.security.authorization;

import java.io.IOException;
import java.util.logging.Logger;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.ssr.springbootjwt.web.security.token.AccessToken;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private Logger logger = Logger.getLogger(JwtAuthorizationFilter.class.getName());
    private final AccessToken accessToken;

    public JwtAuthorizationFilter(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // request header has accesstoken checked with JwtAuthorizationManager
        var jwt = accessToken.get(request);
        try {
            accessToken.verify(jwt);
        } catch (JWTVerificationException e) {
            logger.severe("authorization failed");
            // handle AccessDeniedHandler if authentication not annonymous or rememberme
            SecurityContextHolder.getContext().setAuthentication(null);
            throw new AccessDeniedException("authorization failed", e);
        }
        filterChain.doFilter(request, response);
    }

}
