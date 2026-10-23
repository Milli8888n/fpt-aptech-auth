package com.fptaptech.auth.repository;

import com.fptaptech.auth.domain.PasswordHistoryEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface PasswordHistoryRepository extends JpaRepository<PasswordHistoryEntity, Long> {

    List<PasswordHistoryEntity> findTop5ByUserIdOrderByCreatedAtDesc(Long userId);

    void deleteByUserId(Long userId);
}
