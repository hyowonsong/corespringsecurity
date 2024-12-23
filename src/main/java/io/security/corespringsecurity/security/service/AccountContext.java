package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.entity.Account;
import lombok.Data;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.ArrayList;

@Getter
public class AccountContext extends User {
    private Account account;

    public AccountContext(Account account, ArrayList<GrantedAuthority> roles) {
        super(account.getUsername(), account.getPassword(), roles);
        this.account = account;
    }
}