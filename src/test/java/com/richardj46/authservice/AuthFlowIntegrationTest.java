package com.richardj46.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import com.richardj46.authservice.entity.Role;
import com.richardj46.authservice.repository.RoleRepository;
import com.richardj46.authservice.role.RoleNames;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthFlowIntegrationTest {

    private static final String PASSWORD = "Str0ng!Pass";

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",
                () -> "jdbc:h2:mem:auth_flow;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE");
        registry.add("spring.datasource.username", () -> "sa");
        registry.add("spring.datasource.password", () -> "");
        registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");
        registry.add("spring.flyway.enabled", () -> "false");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("app.jwt.secret", () -> "test-secret-key-with-at-least-32-chars!!");
        registry.add("app.security.require-https", () -> "false");
    }
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RoleRepository roleRepository;

    @BeforeEach
    void seedRoles() {
        if (roleRepository.findByName(RoleNames.USER).isEmpty()) {
            Role userRole = new Role();
            userRole.setName(RoleNames.USER);
            roleRepository.save(userRole);
        }
        if (roleRepository.findByName(RoleNames.ADMIN).isEmpty()) {
            Role adminRole = new Role();
            adminRole.setName(RoleNames.ADMIN);
            roleRepository.save(adminRole);
        }
    }

    @Test
    void registerLoginRefreshLogout_flow() throws Exception {
        String email = "flow-" + UUID.randomUUID() + "@example.com";

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email));

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        String accessToken = readJsonField(loginResult.getResponse().getContentAsString(), "accessToken");
        var loginCookies = loginResult.getResponse().getCookies();
        assertThat(loginCookies).isNotEmpty();

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.authorities").isArray());

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(loginCookies))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn();

        var rotatedCookies = refreshResult.getResponse().getCookies();
        assertThat(rotatedCookies).isNotEmpty();

        mockMvc.perform(post("/api/auth/logout")
                        .cookie(rotatedCookies))
                .andExpect(status().isNoContent());

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(rotatedCookies))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminEndpoint_requiresAdminRole() throws Exception {
        String email = "user-" + UUID.randomUUID() + "@example.com";

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, PASSWORD)))
                .andExpect(status().isOk());

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, PASSWORD)))
                .andExpect(status().isOk())
                .andReturn();

        String accessToken = readJsonField(loginResult.getResponse().getContentAsString(), "accessToken");

        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden());
    }

    private static String readJsonField(String json, String field) {
        String marker = "\"" + field + "\":\"";
        int start = json.indexOf(marker);
        if (start < 0) {
            throw new IllegalStateException("Field not found: " + field);
        }
        start += marker.length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }
}
