package com.ssr.springbootjwt.web.response;

import lombok.Getter;

public class AccountJson {

    @Getter
    private final long id;

    @Getter
    private final String name;

    public AccountJson(long id, String name) {
        this.id = id;
        this.name = name;
    }

}
