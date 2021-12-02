package com.mycompany.zullgateway.security;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class UserUuidChecker {

    public boolean check(Authentication authentication, String uuid) {
        if (authentication == null || authentication.getCredentials() == null || authentication.getCredentials().toString().length() == 0) {
            return false;
        }
        if (authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals(Role.ADMIN.withPrefix()))) {
            return true;
        }
        @SuppressWarnings("unchecked")
        var credentials = (Map<String, Object>) authentication.getCredentials();
        return uuid.equals(credentials.get(JwtProperties.TOKEN_CLAIM_UUID).toString());
    }
}
