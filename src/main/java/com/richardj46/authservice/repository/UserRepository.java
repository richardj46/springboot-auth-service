package com.richardj46.authservice.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.richardj46.authservice.entity.User;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, UUID> {

    @EntityGraph(attributePaths = "roles")
    Optional<User> findByEmail(String email);

    @EntityGraph(attributePaths = "roles")
    @Override
    Optional<User> findById(UUID id);

    @EntityGraph(attributePaths = "roles")
    @Override
    List<User> findAll();

    boolean existsByEmail(String email);
}
