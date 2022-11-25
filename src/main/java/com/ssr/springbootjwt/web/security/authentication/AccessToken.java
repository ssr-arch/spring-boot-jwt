package com.ssr.springbootjwt.web.security.authentication;

import java.util.Calendar;
import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import jakarta.servlet.http.HttpServletRequest;

public class AccessToken {

    public static final String HEADER_NAME = "X-AUTH-TOKEN";
    public static final String TOKEN_PREFIX = "BEARER ";

    private final String issuer;
    private final Algorithm algorithm;
    private final int expiresMinute;

    public AccessToken(String issuer, Algorithm algorithm, int expiresMinute) {
        this.issuer = issuer;
        this.algorithm = algorithm;
        this.expiresMinute = expiresMinute;
    }

    public String create(CurrentAccount account) {
        var calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.MINUTE, expiresMinute);
        return JWT.create()
                .withIssuer(issuer)
                .withClaim("id", account.getId())
                .withClaim("name", account.getName())
                .withExpiresAt(calendar.toInstant())
                .sign(algorithm);
    }

    public DecodedJWT verify(String jwt) {
        var verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
        return verifier.verify(jwt);
    }

    public String get(HttpServletRequest request) {
        var headerValue = request.getHeader(HEADER_NAME);
        if (headerValue == null) {
            return null;
        }
        if (!headerValue.startsWith(TOKEN_PREFIX)) {
            return null;
        }
        return headerValue.replace(TOKEN_PREFIX, "");
    }

}
