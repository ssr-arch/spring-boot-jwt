package com.ssr.springbootjwt.web.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.auth0.jwt.algorithms.Algorithm;
import com.ssr.springbootjwt.db.repository.AccountRepository;
import com.ssr.springbootjwt.web.security.authentication.AccessToken;
import com.ssr.springbootjwt.web.security.authentication.CustomJwtAuthenticationProvider;
import com.ssr.springbootjwt.web.security.authentication.JwtAuthenticationFailureHandler;
import com.ssr.springbootjwt.web.security.authentication.JwtAuthenticationFilter;
import com.ssr.springbootjwt.web.security.authentication.JwtAuthenticationSuccessHandler;
import com.ssr.springbootjwt.web.security.authorization.JwtAuthorizationFailureHandler;
import com.ssr.springbootjwt.web.security.authorization.JwtAuthorizationManager;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthorizationManager jwtAuthorizationManager)
            throws Exception {
        http.authorizeHttpRequests(autz -> autz
                .requestMatchers(HttpMethod.POST, "/rest/api/v1/token").permitAll()
                .anyRequest().access(jwtAuthorizationManager))
                .exceptionHandling(ex -> ex.authenticationEntryPoint(new JwtAuthorizationFailureHandler()))
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
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
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            AuthenticationManager authenticationManager,
            AccessToken accessToken) {
        return new JwtAuthenticationFilter(
                authenticationManager,
                new AntPathRequestMatcher("/rest/api/v1/token", HttpMethod.POST.name()),
                new JwtAuthenticationSuccessHandler(accessToken),
                new JwtAuthenticationFailureHandler());
    }

    @Bean
    public CustomJwtAuthenticationProvider customJwtAuthenticationProvider(
            PasswordEncoder passwordEncoder,
            AccountRepository accountRepository) {
        return new CustomJwtAuthenticationProvider(passwordEncoder, accountRepository);
    }

    @Bean
    public JwtAuthorizationManager jwtAuthorizationManager(AccessToken accessToken) {
        return new JwtAuthorizationManager(accessToken);
    }

}
