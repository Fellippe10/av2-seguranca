package com.br.app.authapi.infrastructure.util;

import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

public class SanitizationUtil {

    public static String sanitize(String input) {
        if (input == null) {
            return null;
        }
        // Remove qualquer HTML ou script, permitindo apenas texto simples
        return Jsoup.clean(input, Safelist.none());
    }

    public static String sanitizeEmail(String email) {
        if (email == null) {
            return null;
        }
        // Permite apenas o formato básico de email (texto, @, e domínio)
        return Jsoup.clean(email, Safelist.basic()).trim();
    }
}