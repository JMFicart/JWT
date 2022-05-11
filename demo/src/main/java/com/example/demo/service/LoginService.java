package com.example.demo.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.demo.config.JwtProperties;
import com.example.demo.models.form.LoginForm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class LoginService {
    private final AuthenticationManager authManager;
    private final JwtProperties properties;

    public LoginService(AuthenticationManager authManager, JwtProperties properties, JwtProperties jwtProperties) {
        this.authManager = authManager;
        this.properties = jwtProperties;
    }

    public String login(LoginForm form) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(form.getUsername(), form.getPassword());
        authentication = authManager.authenticate(authentication);
        return JWT.create()
                .withSubject(form.getUsername())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + properties.getExpires()))
                .withClaim("roles", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .sign(Algorithm.HMAC512(properties.getSecret()));
    }
}
