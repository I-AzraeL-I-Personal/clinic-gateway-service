package com.mycompany.zullgateway.security;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtUtils {

    @Value("${app.tokenSecret}")
    private String tokenSecret;

    public Claims getAllClaimsFromJwt(String token) {
        return Jwts.parser()
                .setSigningKey(tokenSecret)
                .parseClaimsJws(token)
                .getBody();
    }

    public String getSubjectFromJwt(String token) {
        return getAllClaimsFromJwt(token).getSubject();
    }

    public Collection<? extends GrantedAuthority> getAuthoritiesFromJwt(String token) {
        @SuppressWarnings("unchecked")
        var authorities = (List<String>) getAllClaimsFromJwt(token).get(JwtProperties.TOKEN_CLAIM_AUTHORITIES);
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toUnmodifiableList());
    }

    public UUID getUuidFromJwt(String token) {
        return UUID.fromString((String) getAllClaimsFromJwt(token).get(JwtProperties.TOKEN_CLAIM_UUID));
    }

    public boolean getIsEnabledFromJwt(String token) {
        return (boolean) getAllClaimsFromJwt(token).get(JwtProperties.TOKEN_CLAIM_ISENABLED);
    }

    public boolean isJwtValid(String authToken) {
        try {
            Jwts.parser().setSigningKey(tokenSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
