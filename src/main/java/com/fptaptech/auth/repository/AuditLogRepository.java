package com.fptaptech.auth.repository;

import com.fptaptech.auth.domain.AuditLogEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditLogRepository extends JpaRepository<AuditLogEntity, Long> {

    @Query("SELECT a FROM AuditLogEntity a WHERE " +
           "(:email IS NULL OR :email = '' OR LOWER(a.email) LIKE LOWER(CONCAT('%', :email, '%'))) AND " +
           "(:action IS NULL OR :action = '' OR a.action = :action) AND " +
           "(:status IS NULL OR :status = '' OR a.status = :status)")
    Page<AuditLogEntity> searchAuditLogs(
        @Param("email") String email,
        @Param("action") String action,
        @Param("status") String status,
        Pageable pageable
    );
}
