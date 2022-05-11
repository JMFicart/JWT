package com.example.demo.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.config.JwtProperties;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProperties properties;

    public JwtAuthenticationFilter(JwtProperties properties) {
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("Authorization").substring(7);

        if (token != null) {
            try {
                DecodedJWT jwt = JWT.require(Algorithm.HMAC512(properties.getSecret()))
                        .build()
                        .verify(token);

                // le toke ne doit pas avoir expiré
                if (jwt.getExpiresAt() != null && jwt.getExpiresAt().after(new Date())) {
                    Authentication auth = new UsernamePasswordAuthenticationToken(
                            jwt.getSubject(),
                            "",
                            jwt.getClaim("roles")
                                    .asList(String.class)
                                    .stream()
                                    .map(SimpleGrantedAuthority::new)
                                    .toList()
                    );

                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            }
            catch (JWTVerificationException ignored){}

            filterChain.doFilter(request, response);
        }
    }
}
