package com.ssr.springbootjwt.db.entity;

import org.springframework.security.crypto.password.PasswordEncoder;

import com.ssr.springbootjwt.web.response.AccountJson;
import com.ssr.springbootjwt.web.response.ResponseJson;
import com.ssr.springbootjwt.web.security.authentication.CurrentAccount;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "accounts")
@NoArgsConstructor
public class Account implements ResponseJson<AccountJson> {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private long id;

    @Column(name = "name")
    private String name;

    @Column(name = "password")
    private String password;

    public Account(long id, String name, String password) {
        this.id = id;
        this.name = name;
        this.password = password;
    }

    public boolean equalPassword(String password, PasswordEncoder encoder) {
        return encoder.matches(password, this.password);
    }

    public CurrentAccount getCurrentAccount() {
        return new CurrentAccount(id, name);
    }

    @Override
    public AccountJson toJson() {
        return new AccountJson(id, name);
    }

}
