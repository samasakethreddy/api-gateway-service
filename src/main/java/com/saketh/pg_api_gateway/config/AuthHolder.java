package com.saketh.pg_api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
@Scope("request")
public class AuthHolder {
    private Authentication authentication;

    public Authentication getAuthentication() {
        return authentication;
    }

    public void setAuthentication(Authentication authentication) {
//        this.authentication = authentication;
        this.authentication = SecurityContextHolder.getContext().getAuthentication();
    }

}
