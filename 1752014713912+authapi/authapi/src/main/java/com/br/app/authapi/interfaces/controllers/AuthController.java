package com.br.app.authapi.interfaces.controllers;

import com.br.app.authapi.application.useCase.AuthUseCase;
import com.br.app.authapi.interfaces.dto.LoginRequest;
import com.br.app.authapi.interfaces.dto.LoginResponse;
import com.br.app.authapi.interfaces.dto.RegisterRequest;
import com.br.app.authapi.interfaces.dto.VerifyOtpRequest;
import com.br.app.authapi.domain.model.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthUseCase authUseCase;

    public AuthController(AuthUseCase authUseCase) {
        this.authUseCase = authUseCase;
    }

    @PostMapping("/register")
    @Operation(summary = "Cadastrar usuário", description = "Cadastra um novo usuário com os dados fornecidos")
    @ApiResponse(responseCode = "200", description = "Usuário cadastrado com sucesso")
    @ApiResponse(responseCode = "400", description = "Dados de usuário inválidos ou duplicados")
    @ApiResponse(responseCode = "500", description = "Erro interno no servidor")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        try {
            if (request.getUsername() == null || request.getUsername().isBlank()) {
                logger.warn("Tentativa de registro com username vazio");
                return ResponseEntity.badRequest().body("Username não pode ser vazio");
            }
            if (request.getPassword() == null || request.getPassword().isBlank()) {
                logger.warn("Tentativa de registro com senha vazia");
                return ResponseEntity.badRequest().body("Senha não pode ser vazia");
            }
            if (request.getEmail() == null || request.getEmail().isBlank()) {
                logger.warn("Tentativa de registro com email vazio");
                return ResponseEntity.badRequest().body("Email não pode ser vazio");
            }

            User user = new User();
            user.setUsername(request.getUsername());
            user.setPassword(request.getPassword());
            user.setName(request.getName());
            user.setEmail(request.getEmail());
            user.setProfile(request.getProfile() != null ? request.getProfile() : "USER");
            user.setAuthorizedIp(request.getAuthorizedIp());
            authUseCase.register(user);
            logger.info("Usuário registrado com sucesso: {}", request.getUsername());
            return ResponseEntity.ok("Usuário cadastrado com sucesso");
        } catch (IllegalArgumentException e) {
            logger.error("Erro ao registrar usuário {}: {}", request.getUsername(), e.getMessage());
            return ResponseEntity.badRequest().body("Erro ao registrar usuário: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Erro inesperado ao registrar usuário {}: {}", request.getUsername(), e.getMessage());
            return ResponseEntity.status(500).body("Erro inesperado ao registrar usuário: " + e.getMessage());
        }
    }

    @PostMapping("/login")
    @Operation(summary = "Autenticar usuário", description = "Autentica o usuário com nome de usuário, senha e IP")
    @ApiResponse(responseCode = "200", description = "Autenticação iniciada, OTP enviado")
    @ApiResponse(responseCode = "400", description = "Dados inválidos")
    @ApiResponse(responseCode = "401", description = "Falha na autenticação")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        try {
            if (request.getUsername() == null || request.getUsername().isBlank()) {
                logger.warn("Tentativa de login com username vazio");
                return ResponseEntity.badRequest().body(new LoginResponse(null, "Username não pode ser vazio"));
            }
            if (request.getPassword() == null || request.getPassword().isBlank()) {
                logger.warn("Tentativa de login com senha vazia");
                return ResponseEntity.badRequest().body(new LoginResponse(null, "Senha não pode ser vazia"));
            }

            String clientIp = httpRequest.getRemoteAddr();
            String token = authUseCase.authenticate(request.getUsername(), request.getPassword(), clientIp);
            logger.info("Autenticação iniciada para usuário: {}. OTP enviado.", request.getUsername());
            return ResponseEntity.ok(new LoginResponse(token, "Autenticação iniciada. OTP enviado para o email. Token: " + token));
        } catch (IllegalArgumentException e) {
            logger.error("Falha na autenticação para usuário {}: {}", request.getUsername(), e.getMessage());
            return ResponseEntity.status(401).body(new LoginResponse(null, "Falha na autenticação: " + e.getMessage()));
        } catch (Exception e) {
            logger.error("Erro inesperado na autenticação para usuário {}: {}", request.getUsername(), e.getMessage());
            return ResponseEntity.status(500).body(new LoginResponse(null, "Erro inesperado: " + e.getMessage()));
        }
    }

    @PostMapping("/verify-otp")
    @Operation(summary = "Verificar OTP", description = "Verifica o OTP enviado para o e-mail do usuário")
    @ApiResponse(responseCode = "200", description = "OTP verificado com sucesso")
    @ApiResponse(responseCode = "400", description = "Dados inválidos")
    @ApiResponse(responseCode = "401", description = "OTP inválido")
    public ResponseEntity<LoginResponse> verifyOtp(@RequestBody VerifyOtpRequest request) {
        try {
            if (request.getUsername() == null || request.getUsername().isBlank()) {
                logger.warn("Tentativa de verificação OTP com username vazio");
                return ResponseEntity.badRequest().body(new LoginResponse(null, "Username não pode ser vazio"));
            }
            if (request.getOtp() == null || request.getOtp().isBlank()) {
                logger.warn("Tentativa de verificação OTP com OTP vazio para username: {}", request.getUsername());
                return ResponseEntity.badRequest().body(new LoginResponse(null, "OTP não pode ser vazio"));
            }

            String token = authUseCase.verifyOtp(request.getUsername(), request.getOtp());
            logger.info("OTP verificado com sucesso para usuário: {}", request.getUsername());
            return ResponseEntity.ok(new LoginResponse(token, "OTP verificado com sucesso. Token: " + token));
        } catch (IllegalArgumentException e) {
            logger.error("Erro ao verificar OTP para usuário {}: {}", request.getUsername(), e.getMessage());
            return ResponseEntity.status(401).body(new LoginResponse(null, "Erro ao verificar OTP: " + e.getMessage()));
        } catch (Exception e) {
            logger.error("Erro inesperado ao verificar OTP para usuário {}: {}", request.getUsername(), e.getMessage());
            return ResponseEntity.status(500).body(new LoginResponse(null, "Erro inesperado: " + e.getMessage()));
        }
    }
}