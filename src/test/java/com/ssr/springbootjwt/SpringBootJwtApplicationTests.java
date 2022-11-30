package com.ssr.springbootjwt;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Calendar;
import java.util.Date;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssr.springbootjwt.web.security.token.AccessToken;
import com.ssr.springbootjwt.web.security.token.RefreshToken;

@SpringBootTest
@AutoConfigureMockMvc
class SpringBootJwtApplicationTests {

    @Autowired
    MockMvc mockMvc;

    @Test
    void generateTokenTest() throws Exception {
        var endPoint = "/rest/api/v1/token";
        var result = mockMvc.perform(MockMvcRequestBuilders
                .post(endPoint)
                .param("username", "username1")
                .param("password", "password"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();
        var body = result.getResponse().getContentAsString();
        System.out.println(body);
    }

    @Test
    void authorizeTest() throws Exception {
        // expire after 10 minutes
        var accessToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VyX25hbWUiOiJ1c2VybmFtZTEiLCJpc3MiOiJjb20uc3NyIiwiZXhwIjoxNjY5NzA3MzY5LCJpYXQiOjE2Njk3MDY3Njl9.IOmMogKnQjWUMHqudryBbjLFDg5i-Gaihu3xmI5EYOg";
        var refreshToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VyX25hbWUiOiJ1c2VybmFtZTEiLCJpc3MiOiJjb20uc3NyIiwiZXhwIjoxNjcwMzc0MjU0LCJpYXQiOjE2Njk3Njk0NTR9.TZ2VDA2-_qFU-Wi52ujkcodXxoI0dZ3Z1M3iYkN7KlE";
        var endPoint = "/rest/api/v1/accounts";
        mockMvc.perform(MockMvcRequestBuilders
                .get(endPoint)
                .header("X-AUTH-TOKEN", "BEARER " + accessToken)
                .header("Referesh-Token", refreshToken))
                .andDo(MockMvcResultHandlers.print());
    }

    @Test
    void refreshTest() throws Exception {
        var accessToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VyX25hbWUiOiJ1c2VybmFtZTEiLCJpc3MiOiJjb20uc3NyIiwiZXhwIjoxNjY5NzA3MzY5LCJpYXQiOjE2Njk3MDY3Njl9.IOmMogKnQjWUMHqudryBbjLFDg5i-Gaihu3xmI5EYOg";
        var refreshToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VyX25hbWUiOiJ1c2VybmFtZTEiLCJpc3MiOiJjb20uc3NyIiwiZXhwIjoxNjcwMzc0MjU0LCJpYXQiOjE2Njk3Njk0NTR9.TZ2VDA2-_qFU-Wi52ujkcodXxoI0dZ3Z1M3iYkN7KlE";
        var endPoint = "/rest/api/v1/token/refresh";
        var result = mockMvc.perform(MockMvcRequestBuilders
                .post(endPoint)
                .header("X-AUTH-TOKEN", "BEARER " + accessToken)
                .header("Refresh-Token", refreshToken))
                .andDo(MockMvcResultHandlers.print())
                .andReturn();
        var bodyJson = new ObjectMapper().readTree(result.getResponse().getContentAsString());
        var newAccessToken = bodyJson.get(AccessToken.KEY);
        var newRefreshToken = bodyJson.get(RefreshToken.KEY);
        System.out.println(newAccessToken);
        System.out.println(newRefreshToken);
    }

    @Test
    void expiredTest() throws InterruptedException {
        var issuer = "test";
        var algorithm = Algorithm.HMAC256("secret");
        var calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.SECOND, 1);
        Thread.sleep(2000);
        var jwt = JWT.create()
                .withIssuer(issuer)
                .withClaim("name", "username")
                .withExpiresAt(calendar.toInstant())
                .sign(algorithm);
        var verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
        var ex = assertThrows(TokenExpiredException.class, () -> {
            verifier.verify(jwt);
        });
        System.out.println(ex.getMessage());
    }

}
