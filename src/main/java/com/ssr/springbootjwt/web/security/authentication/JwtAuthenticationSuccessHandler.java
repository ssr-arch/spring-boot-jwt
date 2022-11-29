package com.ssr.springbootjwt.web.security.authentication;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssr.springbootjwt.web.security.token.AccessToken;
import com.ssr.springbootjwt.web.security.token.RefreshToken;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private Logger logger = Logger.getLogger(JwtAuthenticationSuccessHandler.class.getName());

    private final AccessToken accessToken;
    private final RefreshToken refreshToken;

    public JwtAuthenticationSuccessHandler(AccessToken accessToken, RefreshToken refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        // TODO create reflesh token
        var currentAccount = (CurrentAccount) authentication.getPrincipal();
        var access = accessToken.create(currentAccount);
        var refresh = refreshToken.create(currentAccount);
        var message = "authentication successfully";
        logger.info(message);
        Map<String, String> body = new HashMap<>();
        body.put(AccessToken.KEY, access);
        body.put(RefreshToken.KEY, refresh);
        body.put("message", message);
        response.setStatus(HttpStatus.OK.value());
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
    }

}
