package com.github.sidneymiranda.authservice.repository;

import com.github.sidneymiranda.authservice.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<UserDetails> findByLogin(String login);
}
