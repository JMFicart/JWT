package com.example.demo.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
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

    public LoginService(AuthenticationManager authManager) {
        this.authManager = authManager;
    }

    public String login(LoginForm form) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(form.getUsername(), form.getPassword());
        authentication = authManager.authenticate(authentication);
        return JWT.create()
                .withSubject(form.getUsername())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 86_400_000))
                .withClaim("roles", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .sign(Algorithm.HMAC512("m0N_Sup3r_C0d3_S3creT"));
    }
}
