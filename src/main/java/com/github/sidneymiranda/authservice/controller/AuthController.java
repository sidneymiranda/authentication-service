package com.github.sidneymiranda.authservice.controller;

import com.github.sidneymiranda.authservice.domain.infra.security.TokenService;
import com.github.sidneymiranda.authservice.domain.user.AuthenticationDTO;
import com.github.sidneymiranda.authservice.domain.user.RegisterDTO;
import com.github.sidneymiranda.authservice.domain.user.RegisterResponse;
import com.github.sidneymiranda.authservice.domain.user.User;
import com.github.sidneymiranda.authservice.domain.user.domain.infra.security.LoginResponseDTO;
import com.github.sidneymiranda.authservice.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final TokenService tokenService;

    public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository, TokenService tokenService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.tokenService = tokenService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid AuthenticationDTO authRequest) {
        var usernamePassword = new UsernamePasswordAuthenticationToken(authRequest.login(), authRequest.password());

        var auth = this.authenticationManager.authenticate(usernamePassword);

        var token = tokenService.generateToken((User) auth.getPrincipal());

        return ResponseEntity.ok(new LoginResponseDTO(token));
    }

    @PostMapping("/register")
    @Transactional
    public ResponseEntity<RegisterResponse> register(@RequestBody @Valid RegisterDTO register) {
        if(this.userRepository.findByLogin(register.login()) != null) return ResponseEntity.badRequest().build();

        String encryptedPassword = new BCryptPasswordEncoder().encode(register.password());

        var newUser = new User(register.login(), encryptedPassword, register.role());
        var savedUser = this.userRepository.save(newUser);

        RegisterResponse response = new RegisterResponse("User successfully registered", LocalDateTime.now());
        URI uri = ServletUriComponentsBuilder.fromCurrentRequestUri().path("/register/{id}").buildAndExpand(savedUser).toUri();

        return ResponseEntity.created(uri).body(response);
    }

}
