package com.github.sidneymiranda.authservice.controller;

import com.github.sidneymiranda.authservice.domain.user.User;
import com.github.sidneymiranda.authservice.domain.user.UserRole;
import com.github.sidneymiranda.authservice.infra.security.SecurityConfiguration;
import com.github.sidneymiranda.authservice.infra.security.TokenService;
import com.github.sidneymiranda.authservice.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import({SecurityConfiguration.class})
class AuthControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @MockitoBean
    private TokenService tokenService;

    @MockitoBean
    private UserRepository userRepository;

    @Test
    void loginIsPublic() throws Exception {
        var user = new User("user", "pass", UserRole.USER.name());
        when(this.authenticationManager.authenticate(any()))
                .thenReturn(new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()));
        when(this.tokenService.generateToken(any(User.class))).thenReturn("jwt-token");

        this.mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"user\",\"password\":\"pass\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-token"));
    }

    @Test
    void registerIsPublic() throws Exception {
        when(this.userRepository.findByLogin("newuser")).thenReturn(Optional.empty());
        when(this.userRepository.save(any(User.class)))
                .thenAnswer(invocation -> {
                    User user = invocation.getArgument(0);
                    user.setId("generated-id");
                    return user;
                });

        this.mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"newuser\",\"password\":\"D(j3i4ois8\"}"))
                .andExpect(status().isCreated());
    }

    @Test
    void registerWhenUserAlreadyExistsReturns409() throws Exception {
        when(this.userRepository.findByLogin("existinguser")).thenReturn(Optional.of(new User("existinguser", "hashed-password", UserRole.USER.name())));

        this.mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"existinguser\",\"password\":\"D(j3i4ois8\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.title").value("User already exists"))
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.detail").value("A user with the login already exists: existinguser"));
    }

    @Test
    void registerAdminWithoutAuthenticationReturns401() throws Exception {
        this.mockMvc.perform(post("/auth/register/admin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"newadmin\",\"password\":\"D(j3i4ois8\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser
    void registerAdminWithNonAdminUserReturns403() throws Exception {
        this.mockMvc.perform(post("/auth/register/admin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"newadmin\",\"password\":\"D(j3i4ois8\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void registerAdminWithExplicitTrueCreatesAdminRole() throws Exception {
        when(this.userRepository.findByLogin("newadmin")).thenReturn(Optional.empty());
        when(this.userRepository.save(any(User.class)))
                .thenAnswer(invocation -> {
                    User user = invocation.getArgument(0);
                    user.setId("generated-id");
                    return user;
                });

        this.mockMvc.perform(post("/auth/register/admin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"newadmin\",\"password\":\"D(j3i4ois8\",\"isAdmin\":true}"))
                .andExpect(status().isCreated());

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(this.userRepository).save(userCaptor.capture());
        assertEquals(UserRole.ADMIN, userCaptor.getValue().getRole());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void registerAdminWithExplicitFalseDefaultsToUserRole() throws Exception {
        when(this.userRepository.findByLogin("newuser")).thenReturn(Optional.empty());
        when(this.userRepository.save(any(User.class)))
                .thenAnswer(invocation -> {
                    User user = invocation.getArgument(0);
                    user.setId("generated-id");
                    return user;
                });

        this.mockMvc.perform(post("/auth/register/admin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"newuser\",\"password\":\"D(j3i4ois8\",\"isAdmin\":false}"))
                .andExpect(status().isCreated());

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(this.userRepository).save(userCaptor.capture());
        assertEquals(UserRole.USER, userCaptor.getValue().getRole());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void registerAdminWithNullIsAdminDefaultsToUserRole() throws Exception {
        when(this.userRepository.findByLogin("newuser")).thenReturn(Optional.empty());
        when(this.userRepository.save(any(User.class)))
                .thenAnswer(invocation -> {
                    User user = invocation.getArgument(0);
                    user.setId("generated-id");
                    return user;
                });

        this.mockMvc.perform(post("/auth/register/admin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"newuser\",\"password\":\"D(j3i4ois8\"}"))
                .andExpect(status().isCreated());

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(this.userRepository).save(userCaptor.capture());
        assertEquals(UserRole.USER, userCaptor.getValue().getRole());
    }

    @Test
    void protectedEndpointWithoutTokenReturns401() throws Exception {
        this.mockMvc.perform(get("/any-protected-resource"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser
    void protectedEndpointWithAuthenticatedUserPassesAuthorization() throws Exception {
        this.mockMvc.perform(get("/any-protected-resource"))
                .andExpect(status().isNotFound());
    }
}
