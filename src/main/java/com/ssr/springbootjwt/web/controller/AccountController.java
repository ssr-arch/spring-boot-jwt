package com.ssr.springbootjwt.web.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ssr.springbootjwt.db.entity.Account;
import com.ssr.springbootjwt.web.response.AccountJson;
import com.ssr.springbootjwt.web.service.AccountService;

@RestController
@RequestMapping(path = "/rest/api/v1")
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/accounts")
    public List<AccountJson> fetchAccounts() {
        return accountService.findAll().stream().map(Account::toJson).toList();
    }

}
