package com.richardj46.authservice.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.richardj46.authservice.entity.RefreshToken;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Modifying
    @Query("UPDATE RefreshToken r SET r.revokedAt = :now WHERE r.id = :id AND r.revokedAt IS NULL")
    int revokeById(@Param("id") UUID id, @Param("now") Instant now);
}
