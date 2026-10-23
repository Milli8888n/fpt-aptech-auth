package com.fptaptech.auth.repository;

import com.fptaptech.auth.domain.RecoveryCodeEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface RecoveryCodeRepository extends JpaRepository<RecoveryCodeEntity, Long> {

    List<RecoveryCodeEntity> findByUserIdAndUsedFalse(Long userId);

    void deleteByUserId(Long userId);
}
