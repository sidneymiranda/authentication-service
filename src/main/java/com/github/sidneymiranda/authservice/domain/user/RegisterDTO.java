package com.github.sidneymiranda.authservice.domain.user;

import com.github.sidneymiranda.authservice.controller.validator.ValidPassword;

public record RegisterDTO(String login, @ValidPassword String password, Boolean isAdmin) {
}
