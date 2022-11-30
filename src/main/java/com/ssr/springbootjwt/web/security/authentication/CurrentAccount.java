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

    @Override
    public String toString() {
        return String.format(
                "id(%s),name(%s)",
                String.valueOf(id), name);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CurrentAccount)) {
            return false;
        }
        return this.id == ((CurrentAccount) obj).id;
    }

}
