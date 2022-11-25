package com.ssr.springbootjwt.web.service;

import java.util.List;
import java.util.stream.Stream;

import org.springframework.stereotype.Service;

import com.ssr.springbootjwt.db.entity.Account;
import com.ssr.springbootjwt.db.repository.AccountRepository;

@Service
public class AccountService {

    private final AccountRepository accountRepository;

    public AccountService(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    public List<Account> findAll() {
        return accountRepository.findAll();
    }

}
