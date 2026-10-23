package com.fptaptech.auth.security;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.UserStatus;
import com.fptaptech.auth.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Locale;

@Service
public class DatabaseUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final TimingDefenseService timingDefenseService;

    public DatabaseUserDetailsService(UserRepository userRepository, TimingDefenseService timingDefenseService) {
        this.userRepository = userRepository;
        this.timingDefenseService = timingDefenseService;
    }

    public static String normalize(String login) {
        return login == null ? "" : login.trim().toLowerCase(Locale.ROOT);
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String loginInput) throws UsernameNotFoundException {
        String login = normalize(loginInput);

        AppUser user = userRepository.findByUsernameOrEmail(login)
            .orElseThrow(() -> new UsernameNotFoundException("Tài khoản hoặc mật khẩu không chính xác"));

        // Check if temporary lockout (15 minutes) has expired
        if (user.getStatus() == UserStatus.LOCKED && user.getLockedUntil() != null && Instant.now().isAfter(user.getLockedUntil())) {
            user.setStatus(UserStatus.ACTIVE);
            user.setFailedAttempts(0);
            user.setLockedUntil(null);
            userRepository.save(user);
        }

        return new SecurityUser(user);
    }
}
