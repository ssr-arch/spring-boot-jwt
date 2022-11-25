package com.ssr.springbootjwt.web.security.authentication;

import java.io.IOException;
import java.util.logging.Logger;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private Logger logger = Logger.getLogger(JwtAuthenticationSuccessHandler.class.getName());

    private final AccessToken accessToken;

    public JwtAuthenticationSuccessHandler(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        var currentAccount = (CurrentAccount) authentication.getPrincipal();
        var jwt = accessToken.create(currentAccount);
        var message = "Successfully generated a token";
        logger.info(message);
        response.setStatus(HttpStatus.OK.value());
        response.setHeader(AccessToken.HEADER_NAME, AccessToken.TOKEN_PREFIX + jwt);
        response.getWriter().write(message);
    }

}
