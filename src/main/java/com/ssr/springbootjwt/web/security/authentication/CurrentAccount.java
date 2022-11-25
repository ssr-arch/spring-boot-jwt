package com.ssr.springbootjwt.web.security.authentication;

import lombok.Getter;

/**
*  Authentication Principal
*/
public class CurrentAccount {

    @Getter
    private final long id;

    @Getter
    private final String name;

    public CurrentAccount(long id, String name) {
        this.id = id;
        this.name = name;
    }

}
