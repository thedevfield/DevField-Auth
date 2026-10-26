package dev.devfield.auth.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    @Bean
    FilterRegistrationBean<ServiceCredentialFilter> serviceCredentialFilterRegistration(ServiceCredentialFilter filter) {
        var registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, ServiceCredentialFilter credentials) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((request, response, error) -> response.setStatus(HttpServletResponse.SC_UNAUTHORIZED))
                        .accessDeniedHandler((request, response, error) -> response.setStatus(HttpServletResponse.SC_FORBIDDEN)))
                .addFilterBefore(credentials, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/**", "/api/auth/jwks").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/signup", "/api/auth/verify-email", "/api/auth/login",
                                "/api/auth/logout", "/internal/auth/session-token").hasAuthority("SERVICE_BFF")
                        .requestMatchers(HttpMethod.POST, "/internal/auth/session-check").hasAnyAuthority("SERVICE_PROJECT", "SERVICE_INTERVIEW")
                        .anyRequest().denyAll())
                .build();
    }
}
