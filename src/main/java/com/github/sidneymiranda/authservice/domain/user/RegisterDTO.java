package com.github.sidneymiranda.authservice.domain.user;

public record RegisterDTO(String login, String password, UserRole role) {
}
