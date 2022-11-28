package com.ssr.springbootjwt.web.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
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
import com.ssr.springbootjwt.web.security.authentication.AccessToken;
import com.ssr.springbootjwt.web.security.authentication.CustomJwtAuthenticationProvider;
import com.ssr.springbootjwt.web.security.authentication.JwtAuthenticationFailureHandler;
import com.ssr.springbootjwt.web.security.authentication.JwtAuthenticationFilter;
import com.ssr.springbootjwt.web.security.authentication.JwtAuthenticationSuccessHandler;
import com.ssr.springbootjwt.web.security.authorization.JwtAuthorizationFilter;
import com.ssr.springbootjwt.web.security.authorization.JwtAuthorizationManager;
import com.ssr.springbootjwt.web.security.authorization.JwtInValidEntryPoint;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            AccessToken accessToken,
            AuthenticationManager authenticationManager) throws Exception {
        var tokenEndpoint = AntPathRequestMatcher.antMatcher(HttpMethod.POST, "/rest/api/v1/token");
        http.authorizeHttpRequests(autz -> autz
                .requestMatchers(tokenEndpoint).permitAll()
                .anyRequest().access(new JwtAuthorizationManager(accessToken)))
                .addFilterBefore(new JwtAuthenticationFilter(
                        authenticationManager,
                        tokenEndpoint,
                        new JwtAuthenticationSuccessHandler(accessToken),
                        new JwtAuthenticationFailureHandler()),
                        LogoutFilter.class)
                .addFilterAfter(new JwtAuthorizationFilter(
                        accessToken),
                        AuthorizationFilter.class)
                .exceptionHandling(ex -> ex.authenticationEntryPoint(new JwtInValidEntryPoint()))
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
    public AuthenticationManager authenticationManager(
            HttpSecurity http,
            PasswordEncoder passwordEncoder,
            AccountRepository accountRepository) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationProvider(new CustomJwtAuthenticationProvider(passwordEncoder, accountRepository))
                .build();
    }

}
