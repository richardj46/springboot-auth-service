package com.richardj46.authservice.security;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import com.richardj46.authservice.config.CorsProperties;
import com.richardj46.authservice.config.SecurityConfig;
import com.richardj46.authservice.config.SecurityProperties;
import com.richardj46.authservice.controller.AdminUserController;
import com.richardj46.authservice.controller.AuthController;
import com.richardj46.authservice.controller.UserController;
import com.richardj46.authservice.role.RoleNames;
import com.richardj46.authservice.service.AdminUserService;
import com.richardj46.authservice.service.AuthService;
import com.richardj46.authservice.service.UserService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(controllers = {AuthController.class, UserController.class, AdminUserController.class})
@Import({SecurityConfig.class, SecurityErrorHandlers.class})
@EnableConfigurationProperties({CorsProperties.class, SecurityProperties.class})
@TestPropertySource(properties = {
        "app.cors.allowed-origins=http://localhost:5173",
        "app.security.require-https=false",
        "app.security.max-failed-login-attempts=5",
        "app.security.lockout-duration=15m"
})
class AuthorizationSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;
    @MockitoBean
    private UserService userService;
    @MockitoBean
    private AdminUserService adminUserService;
    @MockitoBean
    private DatabaseUserDetailsService databaseUserDetailsService;
    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Test
    void me_requiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void me_allowsAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .with(jwt().jwt(builder -> builder.subject("user@example.com")
                                .claim("roles", List.of(RoleNames.USER)))
                                .authorities(new SimpleGrantedAuthority(RoleNames.USER))))
                .andExpect(status().isOk());
    }

    @Test
    void adminUsers_forbiddenForRegularUser() throws Exception {
        when(adminUserService.listUsers()).thenReturn(List.of());

        mockMvc.perform(get("/api/admin/users")
                        .with(jwt().jwt(builder -> builder.subject("user@example.com")
                                .claim("roles", List.of(RoleNames.USER)))
                                .authorities(new SimpleGrantedAuthority(RoleNames.USER))))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminUsers_allowedForAdmin() throws Exception {
        when(adminUserService.listUsers()).thenReturn(List.of());

        mockMvc.perform(get("/api/admin/users")
                        .with(jwt().jwt(builder -> builder.subject("admin@example.com")
                                .claim("roles", List.of(RoleNames.ADMIN)))
                                .authorities(new SimpleGrantedAuthority(RoleNames.ADMIN))))
                .andExpect(status().isOk());
    }

    @Test
    void register_isPublic() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "new@example.com",
                                  "password": "Str0ng!Pass"
                                }
                                """))
                .andExpect(status().isOk());
    }
}
