package com.ssr.springbootjwt.web.security.authentication;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private Logger logger = Logger.getLogger(JwtAuthenticationFailureHandler.class.getName());

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {
        logger.log(Level.SEVERE, "authentication failed", exception);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.getWriter().write(exception.getMessage());
    }

}
