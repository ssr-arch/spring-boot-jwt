package com.ssr.springbootjwt.web.security.authentication;

import java.util.ArrayList;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.ssr.springbootjwt.db.repository.AccountRepository;

public class CustomJwtAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;
    private final AccountRepository accountRepository;

    public CustomJwtAuthenticationProvider(PasswordEncoder passwordEncoder, AccountRepository accountRepository) {
        this.passwordEncoder = passwordEncoder;
        this.accountRepository = accountRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var username = (String) authentication.getPrincipal();
        var password = (String) authentication.getCredentials();
        var account = accountRepository.findByName(username);
        if (account == null) {
            throw new UsernameNotFoundException("user not found");
        }
        if (!account.equalPassword(password, passwordEncoder)) {
            throw new BadCredentialsException("bad credencial");
        }
        // do not use UserDetailsService in this project
        return UsernamePasswordAuthenticationToken.authenticated(
                account.getCurrentAccount(),
                null,
                new ArrayList<GrantedAuthority>());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
