package com.br.app.authapi.application.useCase;

import com.br.app.authapi.domain.model.User;
import com.br.app.authapi.domain.service.UserDomainService;
import com.br.app.authapi.infrastructure.repository.UserRepository;
import com.br.app.authapi.infrastructure.security.EmailService;
import com.br.app.authapi.infrastructure.util.JwtUtil;
import com.br.app.authapi.infrastructure.util.SanitizationUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AuthUseCase {

    private static final Logger logger = LoggerFactory.getLogger(AuthUseCase.class);

    private final UserRepository userRepository;
    private final UserDomainService userDomainService;
    private final EmailService emailService;
    private final JwtUtil jwtUtil;

    public AuthUseCase(UserRepository userRepository, UserDomainService userDomainService,
                       EmailService emailService, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.userDomainService = userDomainService;
        this.emailService = emailService;
        this.jwtUtil = jwtUtil;
    }

    public void register(User user) throws Exception {
        String sanitizedUsername = SanitizationUtil.sanitize(user.getUsername());
        String sanitizedEmail = SanitizationUtil.sanitizeEmail(user.getEmail());

        userRepository.findByUsername(sanitizedUsername)
                .ifPresent(u -> {
                    logger.warn("Tentativa de registro com username já existente: {}", sanitizedUsername);
                    throw new IllegalArgumentException("Usuário já cadastrado com este username");
                });

        userRepository.findByEmail(sanitizedEmail)
                .ifPresent(u -> {
                    logger.warn("Tentativa de registro com email já existente: {}", sanitizedEmail);
                    throw new IllegalArgumentException("Email já cadastrado");
                });

        user.setUsername(sanitizedUsername);
        user.setName(SanitizationUtil.sanitize(user.getName()));
        user.setEmail(sanitizedEmail);
        user.setProfile(SanitizationUtil.sanitize(user.getProfile()));
        user.setAuthorizedIp(SanitizationUtil.sanitize(user.getAuthorizedIp()));

        userDomainService.validateUserCredentials(user, user.getPassword(), user.getAuthorizedIp());

        userRepository.save(user);
        logger.info("Usuário cadastrado: {}", user.getUsername());
    }

    public String authenticate(String username, String password, String clientIp) throws Exception {
        if (username == null || username.isBlank()) {
            logger.warn("Tentativa de autenticação com username vazio");
            throw new IllegalArgumentException("Username não pode ser vazio");
        }

        String sanitizedUsername = SanitizationUtil.sanitize(username);
        User user = userRepository.findByUsername(sanitizedUsername)
                .orElseThrow(() -> {
                    logger.warn("Usuário não encontrado: {}", sanitizedUsername);
                    return new IllegalArgumentException("Usuário não encontrado");
                });

        String sanitizedPassword = password != null ? SanitizationUtil.sanitize(password) : null;
        String sanitizedClientIp = clientIp != null ? SanitizationUtil.sanitize(clientIp) : null;

        userDomainService.validateUserCredentials(user, sanitizedPassword, sanitizedClientIp);

        String otp = userDomainService.generateOtp(user);
        emailService.sendOtp(user.getEmail(), otp);
        logger.info("OTP enviado para {} para username: {}", user.getEmail(), sanitizedUsername);

        String token = jwtUtil.generateToken(sanitizedUsername, user.getProfile());
        logger.info("Token JWT gerado para username: {}", sanitizedUsername);
        return token;
    }

    public String verifyOtp(String username, String otp) {
        if (username == null || username.isBlank()) {
            logger.warn("Tentativa de verificação OTP com username vazio");
            throw new IllegalArgumentException("Username não pode ser vazio");
        }
        if (otp == null || otp.isBlank()) {
            logger.warn("Tentativa de verificação OTP com OTP vazio para username: {}", username);
            throw new IllegalArgumentException("OTP não pode ser vazio");
        }

        String sanitizedUsername = SanitizationUtil.sanitize(username);
        String sanitizedOtp = SanitizationUtil.sanitize(otp);

        User user = userRepository.findByUsername(sanitizedUsername)
                .orElseThrow(() -> {
                    logger.warn("Usuário não encontrado para verificação OTP: {}", sanitizedUsername);
                    return new IllegalArgumentException("Usuário não encontrado");
                });

        boolean isValid = userDomainService.validateOtp(user, sanitizedOtp);
        logger.info("Verificação OTP para username: {} - {}", sanitizedUsername, isValid ? "Sucesso" : "Falha");
        if (!isValid) {
            throw new IllegalArgumentException("OTP inválido");
        }

        String token = jwtUtil.generateToken(sanitizedUsername, user.getProfile());
        logger.info("Token JWT gerado após verificação OTP para username: {}", sanitizedUsername);
        return token;
    }
}