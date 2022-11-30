package com.ssr.springbootjwt.web.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.auth0.jwt.algorithms.Algorithm;
import com.ssr.springbootjwt.db.repository.AccountRepository;
import com.ssr.springbootjwt.web.security.authentication.CustomJwtAuthenticationProvider;
import com.ssr.springbootjwt.web.security.authentication.JwtAuthenticationFailureHandler;
import com.ssr.springbootjwt.web.security.authentication.JwtAuthenticationFilter;
import com.ssr.springbootjwt.web.security.authentication.JwtAuthenticationSuccessHandler;
import com.ssr.springbootjwt.web.security.authorization.AuthorizationFailureHandler;
import com.ssr.springbootjwt.web.security.authorization.JwtAuthorizationFilter;
import com.ssr.springbootjwt.web.security.authorization.JwtAuthorizationManager;
import com.ssr.springbootjwt.web.security.token.AccessToken;
import com.ssr.springbootjwt.web.security.token.RefreshToken;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            AccessToken accessToken,
            RefreshToken refreshToken,
            AuthenticationManager authenticationManager) throws Exception {
        var tokenEndpoint = AntPathRequestMatcher.antMatcher(HttpMethod.POST, "/rest/api/v1/token");
        var refreshEndpoint = AntPathRequestMatcher.antMatcher(HttpMethod.POST, "/rest/api/v1/token/refresh");
        http.authorizeHttpRequests(autz -> autz
                .requestMatchers(tokenEndpoint, refreshEndpoint).permitAll()
                .anyRequest().access(new JwtAuthorizationManager(accessToken)))
                .addFilterAfter(new JwtAuthenticationFilter(
                        authenticationManager,
                        tokenEndpoint,
                        new JwtAuthenticationSuccessHandler(accessToken, refreshToken),
                        new JwtAuthenticationFailureHandler()),
                        LogoutFilter.class)
                .addFilterAfter(new JwtAuthorizationFilter(
                        accessToken),
                        AuthorizationFilter.class)
                .exceptionHandling(ex -> ex.accessDeniedHandler(new AuthorizationFailureHandler()))
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AccessToken accessToken() {
        return new AccessToken(
                "com.ssr",
                Algorithm.HMAC256("secret"),
                10);
    }

    @Bean
    public RefreshToken refreshToken() {
        return new RefreshToken(
                "com.ssr",
                7,
                Algorithm.HMAC256("secret"));
    }

    @Bean
    public AuthenticationManager authenticationManager(
            HttpSecurity http,
            PasswordEncoder passwordEncoder,
            AccountRepository accountRepository) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationProvider(
                        new CustomJwtAuthenticationProvider(passwordEncoder, accountRepository))
                .build();
    }

}
