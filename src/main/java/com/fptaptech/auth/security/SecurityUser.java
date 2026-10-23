package com.fptaptech.auth.security;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.UserStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Collection;
import java.util.stream.Collectors;

public class SecurityUser implements UserDetails {

    private final Long id;
    private final String email;
    private final String username;
    private final String password;
    private final UserStatus status;
    private final Instant lockedUntil;
    private final boolean totpEnabled;
    private final Collection<? extends GrantedAuthority> authorities;

    public SecurityUser(AppUser user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.username = user.getUsername();
        this.password = user.getPasswordHash();
        this.status = user.getStatus();
        this.lockedUntil = user.getLockedUntil();
        this.totpEnabled = user.isTotpEnabled();
        this.authorities = user.getRoles().stream()
            .map(role -> new SimpleGrantedAuthority(role.getName()))
            .collect(Collectors.toSet());
    }

    public Long getId() { return id; }
    public String getEmail() { return email; }
    public UserStatus getStatus() { return status; }
    public boolean isTotpEnabled() { return totpEnabled; }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        if (status == UserStatus.LOCKED) {
            return lockedUntil != null && Instant.now().isAfter(lockedUntil);
        }
        return status != UserStatus.DISABLED;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return status == UserStatus.ACTIVE;
    }
}
