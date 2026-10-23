package com.fptaptech.auth.repository;

import com.fptaptech.auth.domain.TokenEntity;
import com.fptaptech.auth.domain.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<TokenEntity, Long> {

    Optional<TokenEntity> findByTokenHashAndTokenType(String tokenHash, TokenType tokenType);

    @Query("SELECT COUNT(t) FROM TokenEntity t WHERE t.user.id = :userId AND t.tokenType = :type AND t.createdAt >= :after")
    long countRecentTokens(@Param("userId") Long userId, @Param("type") TokenType type, @Param("after") Instant after);

    void deleteByUserIdAndTokenType(Long userId, TokenType tokenType);
}
