package com.mycompany.zullgateway.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        try {
            String token = parseJwt(request);
            if (token != null && jwtUtils.isJwtValid(token)) {
                String subject = jwtUtils.getSubjectFromJwt(token);
                var authorities = jwtUtils.getAuthoritiesFromJwt(token);
                var credentials = Map.of(
                        JwtProperties.TOKEN_CLAIM_UUID, jwtUtils.getUuidFromJwt(token),
                        JwtProperties.TOKEN_CLAIM_ISENABLED, jwtUtils.getIsEnabledFromJwt(token));

                var authentication = new UsernamePasswordAuthenticationToken(subject, credentials, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            log.error("Cannot set user authentication: {}", e.getMessage());
        }
        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader(JwtProperties.AUTHORIZATION_HEADER);

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith(JwtProperties.TOKEN_PREFIX)) {
            return headerAuth.replace(JwtProperties.TOKEN_PREFIX, "");
        }

        return null;
    }
}
