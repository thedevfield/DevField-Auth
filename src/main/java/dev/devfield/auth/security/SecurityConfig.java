package dev.devfield.auth.security;

import dev.devfield.auth.oauth.OAuthFlowStore;
import dev.devfield.auth.oauth.DiscardingAuthorizedClientRepository;
import dev.devfield.auth.oauth.OAuthIntentResolver;
import dev.devfield.auth.oauth.OAuthProviders;
import dev.devfield.auth.oauth.OAuthRequestRepository;
import dev.devfield.auth.oauth.OAuthResultHandlers;
import dev.devfield.auth.oauth.OAuthStartValidationFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;

@Configuration
public class SecurityConfig {
    @Bean
    FilterRegistrationBean<ServiceCredentialFilter> serviceCredentialFilterRegistration(ServiceCredentialFilter filter) {
        var registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, ServiceCredentialFilter credentials,
                                            OAuthProviders providers, OAuthFlowStore flows,
                                            OAuthRequestRepository requests, OAuthResultHandlers results,
                                            DiscardingAuthorizedClientRepository authorizedClients) throws Exception {
        http.csrf(csrf -> csrf.disable())
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
                                "/api/auth/logout", "/internal/auth/session-token", "/internal/auth/oauth-intents",
                                "/internal/auth/oauth-handoffs/exchange").hasAuthority("SERVICE_BFF")
                        .requestMatchers(HttpMethod.POST, "/internal/auth/session-check").hasAnyAuthority("SERVICE_PROJECT", "SERVICE_INTERVIEW")
                        .requestMatchers(HttpMethod.GET, "/oauth2/authorization/google", "/oauth2/authorization/github",
                                "/oauth2/authorization/kakao", "/login/oauth2/code/google", "/login/oauth2/code/github",
                                "/login/oauth2/code/kakao").permitAll()
                        .anyRequest().denyAll())
                ;
        http.addFilterBefore(new OAuthStartValidationFilter(flows, providers), OAuth2AuthorizationRequestRedirectFilter.class);
        if (providers.anyEnabled()) {
            http.oauth2Login(oauth -> oauth.clientRegistrationRepository(providers)
                    .authorizedClientRepository(authorizedClients)
                    .authorizationEndpoint(auth -> auth.authorizationRequestResolver(new OAuthIntentResolver(providers, flows))
                            .authorizationRequestRepository(requests))
                    .successHandler(results).failureHandler(results));
        }
        return http.build();
    }
}
