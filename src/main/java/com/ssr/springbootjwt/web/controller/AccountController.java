package com.ssr.springbootjwt.web.controller;

import java.util.List;
import java.util.logging.Logger;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ssr.springbootjwt.db.entity.Account;
import com.ssr.springbootjwt.web.response.AccountJson;
import com.ssr.springbootjwt.web.security.authentication.CurrentAccount;
import com.ssr.springbootjwt.web.service.AccountService;

@RestController
@RequestMapping(path = "/rest/api/v1")
public class AccountController {

    private Logger logger = Logger.getLogger(AccountController.class.getName());
    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/accounts")
    public List<AccountJson> fetchAccounts(CurrentAccount currentAccount) {
        logger.info(String.format("account(%s) accessed", currentAccount));
        return accountService.findAll().stream().map(Account::toJsonEntity).toList();
    }

}
