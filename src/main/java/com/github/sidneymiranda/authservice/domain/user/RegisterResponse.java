package com.github.sidneymiranda.authservice.domain.user;

import java.time.LocalDateTime;

public record RegisterResponse(String message, LocalDateTime timestamp) {
}
