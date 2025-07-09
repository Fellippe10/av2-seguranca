package com.br.app.authapi.domain.service;

import com.br.app.authapi.domain.model.User;

public interface UserDomainService {

    void validateUserCredentials(User user, String password, String ip);

    String generateOtp(User user);

    boolean validateOtp(User user, String otp);
}