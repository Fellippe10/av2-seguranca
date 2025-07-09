package com.br.app.authapi.domain.service;

import com.br.app.authapi.domain.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Service
public class UserDomainServiceImpl implements UserDomainService {

    private final Map<String, String> otpStore = new HashMap<>();

    @Value("${auth.validate-ip:true}")
    private boolean validateIp;

    @Override
    public void validateUserCredentials(User user, String password, String ip) {
        // Durante o registro, apenas criptografar a senha
        if (user.getId() == null) {
            if (password == null || password.isBlank()) {
                throw new IllegalArgumentException("Senha não pode ser vazia");
            }
            user.setPassword(hashPassword(password));
            return;
        }

        // Durante autenticação, validar senha e IP, se necessário
        if (password != null) { // Permite password=null para verifyOtp
            if (password.isBlank()) {
                throw new IllegalArgumentException("Senha não pode ser vazia");
            }
            String hashedPassword = hashPassword(password);
            if (!user.getPassword().equals(hashedPassword)) {
                throw new IllegalArgumentException("Senha inválida. Captcha: " + generateCaptcha());
            }
        }

        if (validateIp && ip != null) { // Permite ip=null para verifyOtp
            if (ip.isBlank()) {
                throw new IllegalArgumentException("IP não autorizado");
            }
            if (!user.getAuthorizedIp().equals(ip)) {
                throw new IllegalArgumentException("IP não autorizado");
            }
        }
    }

    @Override
    public String generateOtp(User user) {
        String otp = String.format("%06d", new Random().nextInt(999999));
        otpStore.put(user.getUsername(), otp);
        return otp;
    }

    @Override
    public boolean validateOtp(User user, String otp) {
        String storedOtp = otpStore.get(user.getUsername());
        if (storedOtp == null || !storedOtp.equals(otp)) {
            return false;
        }
        otpStore.remove(user.getUsername());
        return true;
    }

    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Erro ao criptografar senha", e);
        }
    }

    private String generateCaptcha() {
        return String.format("%06d", new Random().nextInt(999999));
    }
}