package io.security.corespringsecurity.domain.entity;

import lombok.Data;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;

@Entity
@Data
public class Account {

    @Id
    @GeneratedValue
    private Long Id;
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}
