package com.br.app.authapi.interfaces.controllers;

import com.br.app.authapi.infrastructure.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/protected")
public class ProtectedRouteController {

    private static final Logger logger = LoggerFactory.getLogger(ProtectedRouteController.class);

    private final JwtUtil jwtUtil;

    public ProtectedRouteController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/resource")
    public ResponseEntity<String> accessProtectedResource() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        logger.info("Acesso ao endpoint protegido por usuário: {}", username);
        return ResponseEntity.ok("Bem-vindo, " + username + "! Este é um recurso protegido.");
    }
}