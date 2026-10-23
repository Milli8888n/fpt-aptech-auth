package com.fptaptech.auth.config;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.Role;
import com.fptaptech.auth.domain.UserStatus;
import com.fptaptech.auth.repository.RoleRepository;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.security.CustomAuthenticationFailureHandler;
import com.fptaptech.auth.security.CustomAuthenticationSuccessHandler;
import com.fptaptech.auth.security.DatabaseUserDetailsService;
import com.fptaptech.auth.security.SessionMetadataFilter;
import com.fptaptech.auth.security.TwoFactorEnforcementFilter;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final DatabaseUserDetailsService userDetailsService;
    private final CustomAuthenticationSuccessHandler successHandler;
    private final CustomAuthenticationFailureHandler failureHandler;
    private final TwoFactorEnforcementFilter twoFactorEnforcementFilter;
    private final SessionMetadataFilter sessionMetadataFilter;
    private final DataSource dataSource;

    public SecurityConfig(
            DatabaseUserDetailsService userDetailsService,
            CustomAuthenticationSuccessHandler successHandler,
            CustomAuthenticationFailureHandler failureHandler,
            TwoFactorEnforcementFilter twoFactorEnforcementFilter,
            SessionMetadataFilter sessionMetadataFilter,
            DataSource dataSource) {
        this.userDetailsService = userDetailsService;
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.twoFactorEnforcementFilter = twoFactorEnforcementFilter;
        this.sessionMetadataFilter = sessionMetadataFilter;
        this.dataSource = dataSource;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/",
                    "/registration",
                    "/login",
                    "/verify-email",
                    "/resend-verification",
                    "/forgot-password",
                    "/reset-password",
                    "/error",
                    "/css/**",
                    "/js/**",
                    "/images/**"
                ).permitAll()
                .requestMatchers("/2fa/**").authenticated()
                .requestMatchers("/profile/**", "/sessions/**", "/change-password").authenticated()
                .requestMatchers("/lecturer/**").hasAnyRole("LECTURER", "ADMIN")
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .successHandler(successHandler)
                .failureHandler(failureHandler)
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .deleteCookies("FPTSESSION", "remember-me")
                .invalidateHttpSession(true)
                .permitAll()
            )
            .rememberMe(remember -> remember
                .tokenRepository(persistentTokenRepository())
                .tokenValiditySeconds(14 * 24 * 60 * 60) // 14 days
                .userDetailsService(userDetailsService)
                .rememberMeParameter("remember-me")
            )
            .sessionManagement(session -> session
                .maximumSessions(2)
                .maxSessionsPreventsLogin(false) // Kick oldest session
                .expiredUrl("/login?expired=true")
            )
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; " +
                    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
                    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
                    "img-src 'self' data: https:; " +
                    "font-src 'self' https://cdn.jsdelivr.net;"
                ))
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)
                )
            )
            .addFilterAfter(twoFactorEnforcementFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(sessionMetadataFilter, TwoFactorEnforcementFilter.class);

        return http.build();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // DelegatingPasswordEncoder with BCrypt as default ({bcrypt}$2a$10$...)
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public CommandLineRunner initialAdminSeeder(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            String adminEmail = "admin@fpt.edu.vn";
            if (!userRepository.existsByEmail(adminEmail)) {
                Role adminRole = roleRepository.findByName(Role.ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(Role.ADMIN)));

                AppUser admin = new AppUser(
                    adminEmail,
                    "admin",
                    passwordEncoder.encode("Admin@Aptech2026!"),
                    UserStatus.ACTIVE
                );
                admin.getRoles().add(adminRole);
                userRepository.save(admin);
            }
        };
    }
}
