package com.github.sidneymiranda.authservice.controller;

import com.github.sidneymiranda.authservice.domain.user.AuthenticationDTO;
import com.github.sidneymiranda.authservice.domain.user.LoginResponseDTO;
import com.github.sidneymiranda.authservice.domain.user.RegisterDTO;
import com.github.sidneymiranda.authservice.domain.user.RegisterResponse;
import com.github.sidneymiranda.authservice.domain.user.User;
import com.github.sidneymiranda.authservice.domain.user.UserRole;
import com.github.sidneymiranda.authservice.exception.UserAlreadyExistsException;
import com.github.sidneymiranda.authservice.infra.security.TokenService;
import com.github.sidneymiranda.authservice.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Objects;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(AuthenticationManager authenticationManager,
                          UserRepository userRepository,
                          TokenService tokenService,
                          PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody @Valid AuthenticationDTO authRequest) {
        var usernamePassword = new UsernamePasswordAuthenticationToken(authRequest.login(), authRequest.password());

        var auth = this.authenticationManager.authenticate(usernamePassword);

        var token = this.tokenService.generateToken((org.springframework.security.core.userdetails.UserDetails) Objects.requireNonNull(auth.getPrincipal()));

        return ResponseEntity.ok(new LoginResponseDTO(token));
    }

    @PostMapping("/register")
    @Transactional
    public ResponseEntity<RegisterResponse> register(@RequestBody @Valid RegisterDTO register) {
        if (this.userRepository.findByLogin(register.login()).isPresent()) {
            throw new UserAlreadyExistsException("A user with the login already exists: " + register.login());
        }

        String encryptedPassword = this.passwordEncoder.encode(register.password());

        var newUser = new User(register.login(), encryptedPassword, UserRole.USER.name());
        var savedUser = this.userRepository.save(newUser);

        RegisterResponse response = new RegisterResponse("User successfully registered", LocalDateTime.now());
        URI uri = ServletUriComponentsBuilder.fromCurrentRequestUri()
                .path("/{id}")
                .buildAndExpand(savedUser.getId())
                .toUri();

        return ResponseEntity.created(uri).body(response);
    }

}
