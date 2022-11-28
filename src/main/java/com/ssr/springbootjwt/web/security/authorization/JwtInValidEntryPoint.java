package com.ssr.springbootjwt.web.security.authorization;

import java.io.IOException;
import java.util.logging.Logger;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/*
*  
*/
public class JwtInValidEntryPoint implements AuthenticationEntryPoint {

    private Logger logger = Logger.getLogger(JwtInValidEntryPoint.class.getName());

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
        var message = authException.getMessage();
        logger.severe(message);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.getWriter().write(message);
    }

}
