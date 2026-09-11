package com.github.sidneymiranda.authservice.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.github.sidneymiranda.authservice.domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Service
public class TokenService {

    private static final int HMAC256_MIN_SECRET_LENGTH = 32;

    private final Algorithm algorithm;
    private final String issuer;
    private final Duration expiration;

    public TokenService(
            @Value("${api.security.token.secret}") String secret,
            @Value("${api.security.token.issuer:auth-service}") String issuer,
            @Value("${api.security.token.expiration-hours:1}") long expirationHours) {
        if (secret == null || secret.length() < HMAC256_MIN_SECRET_LENGTH) {
            throw new IllegalStateException(
                    "api.security.token.secret deve ter ao menos 32 caracteres (256 bits) para HMAC256");
        }
        this.algorithm = Algorithm.HMAC256(secret);
        this.issuer = issuer;
        this.expiration = Duration.ofHours(expirationHours);
    }

    public String generateToken(UserDetails user) {
        try {
            return JWT.create()
                    .withIssuer(this.issuer)
                    .withSubject(user.getUsername())
                    .withExpiresAt(Instant.now().plus(this.expiration))
                    .sign(this.algorithm);
        } catch (JWTCreationException exception) {
            throw new IllegalStateException("Error in token generation.", exception);
        }
    }

    public Optional<String> validateToken(String token) {
        try {
            return Optional.ofNullable(JWT.require(this.algorithm)
                    .withIssuer(this.issuer)
                    .build()
                    .verify(token)
                    .getSubject());
        } catch (JWTVerificationException exception) {
            return Optional.empty();
        }
    }

}
