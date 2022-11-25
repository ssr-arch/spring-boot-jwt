package com.ssr.springbootjwt;

import static org.junit.jupiter.api.Assertions.assertNotNull;
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
				.andExpect(MockMvcResultMatchers.header().exists("X-AUTH-TOKEN"))
				.andReturn();
		var token = result.getResponse().getHeader("X-AUTH-TOKEN");
		assertNotNull(token);
		var jwt = token.replace("BEARER ", "");
		System.out.println(jwt);
	}

	@Test
	void authorizeTest() throws Exception {
		// expire after 10 minutes
		var jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjb20uc3NyIiwibmFtZSI6InVzZXJuYW1lMSIsImlkIjoxLCJleHAiOjE2NjkzNTgwMDJ9.B7ikxd0BY6bA0RaqYVuEIyuuQ2MbWxklpqAlWgPoR4U";
		var endPoint = "/rest/api/v1/accounts";
		mockMvc.perform(MockMvcRequestBuilders
				.get(endPoint)
				.header("X-AUTH-TOKEN", "BEARER " + jwt))
				.andDo(MockMvcResultHandlers.print());
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
