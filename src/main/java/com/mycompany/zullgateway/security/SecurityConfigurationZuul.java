package com.mycompany.zullgateway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfigurationZuul extends WebSecurityConfigurerAdapter {

    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .csrf().disable()
                .logout().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling().authenticationEntryPoint((request, response, e) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)

                .authorizeRequests()

                .antMatchers("/error").permitAll()
                .antMatchers("/actuator/routes").permitAll()

                .antMatchers(HttpMethod.POST, "/api/doctor").hasRole(Role.DOCTOR.name())
                .antMatchers(HttpMethod.PUT, "/api/doctor/{doctorUUID}").access("@userUuidChecker.check(authentication, #doctorUUID)")
                .antMatchers(HttpMethod.DELETE, "/api/doctor/{doctorUUID}").access("@userUuidChecker.check(authentication, #doctorUUID)")
                .antMatchers(HttpMethod.GET, "/api/doctor/voivodeships").permitAll()
                .antMatchers(HttpMethod.GET, "/api/doctor").authenticated()
                .antMatchers(HttpMethod.GET, "/api/doctor/{doctorUUID}").access("@userUuidChecker.check(authentication, #doctorUUID)")
                .antMatchers(HttpMethod.GET, "/api/doctor/{doctorUUID}/with-contact").access("@userUuidChecker.check(authentication, #doctorUUID)")
                .antMatchers(HttpMethod.GET, "/api/doctor/{doctorUUID}/with-workdays").access("@userUuidChecker.check(authentication, #doctorUUID)")
                .antMatchers(HttpMethod.GET, "/api/doctor/{doctorUUID}/with-contact-and-workdays").access("@userUuidChecker.check(authentication, #doctorUUID)")

                .antMatchers(HttpMethod.POST, "/api/patient").hasRole(Role.PATIENT.name())
                .antMatchers(HttpMethod.PUT, "/api/patient/{patientUUID}").access("@userUuidChecker.check(authentication, #patientUUID)")
                .antMatchers(HttpMethod.DELETE, "/api/patient/{patientUUID}").access("@userUuidChecker.check(authentication, #patientUUID)")
                .antMatchers(HttpMethod.GET, "/api/patient/voivodeships").permitAll()
                .antMatchers(HttpMethod.GET, "/api/patient/{patientUUID}").access("@userUuidChecker.check(authentication, #patientUUID)")
                .antMatchers(HttpMethod.GET, "/api/patient/{patientUUID}/with-contact").access("@userUuidChecker.check(authentication, #patientUUID)")

                .antMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                .antMatchers(HttpMethod.POST, "/api/auth/users").permitAll()
                .antMatchers(HttpMethod.PUT, "/api/auth/users/{userUUID}").access("@userUuidChecker.check(authentication, #userUUID)")
                .antMatchers(HttpMethod.DELETE, "/api/auth/users/{userUUID}").access("@userUuidChecker.check(authentication, #userUUID)")
                .antMatchers(HttpMethod.PATCH, "/api/auth/users/{userUUID}").hasRole(Role.ADMIN.name())
                .antMatchers(HttpMethod.GET, "/api/auth/users/pending").hasRole(Role.ADMIN.name())

                .antMatchers(HttpMethod.POST, "/api/appointment").hasRole(Role.PATIENT.name())
                .antMatchers(HttpMethod.GET, "/api/appointment/find").authenticated()
                .antMatchers(HttpMethod.GET, "/api/appointment/patient/{patientUUID}").access("@userUuidChecker.check(authentication, #patientUUID)")
                .antMatchers(HttpMethod.GET, "/api/appointment/doctor/{doctorUUID}").hasRole(Role.DOCTOR.name())

                //authorize further for specific access in appointment service
                .antMatchers(HttpMethod.DELETE, "/api/appointment/{id}").authenticated()
                .antMatchers(HttpMethod.POST, "/api/appointment/{id}/details").hasRole(Role.DOCTOR.name())
                .antMatchers(HttpMethod.GET, "/api/appointment/{id}/details").hasAnyRole(Role.DOCTOR.name(), Role.PATIENT.name())
                .antMatchers(HttpMethod.GET, "/api/appointment/{id}/details/prescription").hasAnyRole(Role.DOCTOR.name(), Role.PATIENT.name())
                .antMatchers(HttpMethod.GET, "/api/appointment/{id}/details/attachment").hasAnyRole(Role.DOCTOR.name(), Role.PATIENT.name())

                .antMatchers("/**").hasRole(Role.ADMIN.name())
                .anyRequest().denyAll();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Collections.singletonList("*"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(Arrays.asList(
                "Access-Control-Allow-Headers",
                "Access-Control-Allow-Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
                "Origin","Cache-Control",
                "Content-Type",
                "Authorization",
                "Pragma"
        ));
        configuration.setAllowedMethods(Arrays.asList("DELETE", "GET", "POST", "PUT", "OPTIONS", "PATCH"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        var hierarchy = new RoleHierarchyImpl();
        var prefix = "ROLE_";
        hierarchy.setHierarchy(String.format("%1$s > %2$s\n%1$s > %3$s\n%3$s > %2$s",
                prefix + Role.ADMIN.name(),
                prefix + Role.PATIENT.name(),
                prefix +Role.DOCTOR.name()));
        return hierarchy;
    }
}
