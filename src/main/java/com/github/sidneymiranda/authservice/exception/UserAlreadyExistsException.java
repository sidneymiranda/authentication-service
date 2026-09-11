package com.github.sidneymiranda.authservice.exception;

/**
 * Thrown when an attempt is made to register a user with a login that is already in use.
 */
public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException(String message) {
        super(message);
    }
}
