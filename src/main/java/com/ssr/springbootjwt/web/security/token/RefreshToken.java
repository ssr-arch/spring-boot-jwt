package com.ssr.springbootjwt.web.security.token;

import java.util.Calendar;
import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.ssr.springbootjwt.web.security.authentication.CurrentAccount;

import jakarta.servlet.http.HttpServletRequest;

public class RefreshToken {

    public static String REQUEST_HEADER = "Refresh-Token";
    public static String KEY = "refresh_token";

    private final String issuer;
    private final int expiryDay;
    private final Algorithm algorithm;

    public RefreshToken(String issuer, int expiryDay, Algorithm algorithm) {
        this.issuer = issuer;
        this.expiryDay = expiryDay;
        this.algorithm = algorithm;
    }

    public String create(CurrentAccount account) {
        var calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, expiryDay);
        return JWT.create()
                .withIssuer(issuer)
                .withClaim("user_id", account.getId())
                .withClaim("user_name", account.getName())
                .withIssuedAt(new Date())
                .withExpiresAt(calendar.toInstant())
                .sign(algorithm);
    }

    public CurrentAccount getCurrentAccountWithNoVerify(HttpServletRequest request) {
        var token = request.getHeader(REQUEST_HEADER);
        var decoded = JWT.decode(token);
        return new CurrentAccount(
                decoded.getClaim("user_id").asLong(),
                decoded.getClaim("user_name").asString());
    }

    public String get(HttpServletRequest request) {
        return request.getHeader(KEY);
    }

    public DecodedJWT verify(String token) {
        var verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }

}
