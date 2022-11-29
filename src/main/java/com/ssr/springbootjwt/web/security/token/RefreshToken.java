package com.ssr.springbootjwt.web.security.token;

import java.util.Calendar;
import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.ssr.springbootjwt.web.security.authentication.CurrentAccount;

public class RefreshToken {

    public static String KEY = "refresh_token";

    private final String issuer;
    private final int expiryDay;
    private final Algorithm algorithm;

    public RefreshToken(String issuer, int expiryDay, Algorithm algorithm) {
        this.issuer = issuer;
        this.expiryDay = expiryDay;
        this.algorithm = algorithm;
    }

    public String create(CurrentAccount account) throws JsonProcessingException {
        var calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, expiryDay);
        return JWT.create()
                .withIssuer(issuer)
                .withClaim("user_id", String.valueOf(account.getId()))
                .withClaim("user_name", account.getName())
                .withIssuedAt(new Date())
                .withExpiresAt(calendar.toInstant())
                .sign(algorithm);
    }

}
