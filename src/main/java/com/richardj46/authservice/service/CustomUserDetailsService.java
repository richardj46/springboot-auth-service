package com.richardj46.authservice.service;

import com.richardj46.authservice.entity.User;
import com.richardj46.authservice.repository.UserRepository;

import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;


@Service
public class CustomUserDetailsService 
        implements UserDetailsService {


    private final UserRepository repository;


    public CustomUserDetailsService(
            UserRepository repository) {
        this.repository = repository;
    }


    @Override
    public UserDetails loadUserByUsername(
            String username) {

        User user = repository
                .findByUsername(username)
                .orElseThrow(() ->
                    new UsernameNotFoundException(
                       "User not found"
                    )
                );


        return org.springframework.security.core.userdetails.User
                .builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole())
                .build();
    }
}