package com.ssr.springbootjwt.web.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssr.springbootjwt.web.security.token.AccessToken;
import com.ssr.springbootjwt.web.security.token.RefreshToken;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(path = "/rest/api/v1/token")
public class TokenController {

    private final AccessToken accessToken;

    private final RefreshToken refreshToken;

    public TokenController(AccessToken accessToken, RefreshToken refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    @PostMapping(path = "/refresh")
    public String recreateAccessToken(HttpServletRequest request) throws JsonProcessingException {
        // TODO refresh test
        var accessAccount = accessToken.getCurrentAccountWithNoVerify(request);
        var refreshAccount = refreshToken.getCurrentAccountWithNoVerify(request);
        if (!accessAccount.equals(refreshAccount)) {
            return "refresh token expired";
        }
        var newAccessToken = accessToken.create(accessAccount);
        var newRefreshToken = refreshToken.create(refreshAccount);
        Map<String, String> body = new HashMap<>();
        body.put(AccessToken.KEY, newAccessToken);
        body.put(RefreshToken.KEY, newRefreshToken);
        return new ObjectMapper().writeValueAsString(body);
    }

}
