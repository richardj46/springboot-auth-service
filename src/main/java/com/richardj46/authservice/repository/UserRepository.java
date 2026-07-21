package com.richardj46.authservice.repository;

import com.richardj46.authservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository 
        extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
}