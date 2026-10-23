package com.fptaptech.auth.repository;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<AppUser, Long> {

    @EntityGraph(attributePaths = "roles")
    Optional<AppUser> findByUsername(String username);

    @EntityGraph(attributePaths = "roles")
    Optional<AppUser> findByEmail(String email);

    @EntityGraph(attributePaths = "roles")
    @Query("SELECT u FROM AppUser u WHERE u.username = :login OR u.email = :login")
    Optional<AppUser> findByUsernameOrEmail(@Param("login") String login);

    boolean existsByUsername(String username);
    boolean existsByEmail(String email);

    @Query("SELECT COUNT(u) FROM AppUser u JOIN u.roles r WHERE r.name = :roleName AND u.status = :status")
    long countByRoleNameAndStatus(@Param("roleName") String roleName, @Param("status") UserStatus status);

    @EntityGraph(attributePaths = "roles")
    @Query("SELECT DISTINCT u FROM AppUser u LEFT JOIN u.roles r WHERE " +
           "(:query IS NULL OR :query = '' OR LOWER(u.username) LIKE LOWER(CONCAT('%', :query, '%')) OR LOWER(u.email) LIKE LOWER(CONCAT('%', :query, '%'))) AND " +
           "(:role IS NULL OR :role = '' OR r.name = :role) AND " +
           "(:status IS NULL OR u.status = :status)")
    Page<AppUser> searchUsers(
        @Param("query") String query,
        @Param("role") String role,
        @Param("status") UserStatus status,
        Pageable pageable
    );

    @EntityGraph(attributePaths = "roles")
    @Query("SELECT DISTINCT u FROM AppUser u JOIN u.roles r WHERE r.name = 'ROLE_STUDENT'")
    Page<AppUser> findAllStudents(Pageable pageable);
}
