package com.ssr.springbootjwt.web.security.authorization;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class AuthorizationFailureHandler implements AccessDeniedHandler {

    private Logger logger = Logger.getLogger(AuthorizationFailureHandler.class.getName());

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException, ServletException {
        var cause = accessDeniedException.getCause();
        var message = cause.getMessage();
        logger.severe(message);
        Map<String, String> body = new HashMap<>();
        body.put("message", message);
        if (cause instanceof TokenExpiredException) {
            body.put("error", "expired token");
        } else {
            body.put("error", "invalid token");
        }
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
    }

}
