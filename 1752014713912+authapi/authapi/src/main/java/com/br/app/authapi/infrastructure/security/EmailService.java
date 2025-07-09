package com.br.app.authapi.infrastructure.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    public void sendOtp(String email, String otp) {
        logger.info("Enviando OTP {} para {}", otp, email);
    }
}