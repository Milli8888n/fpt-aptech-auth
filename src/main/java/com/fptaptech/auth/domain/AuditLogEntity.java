package com.fptaptech.auth.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_logs")
public class AuditLogEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_time", nullable = false)
    private Instant eventTime;

    @Column(nullable = false, length = 100)
    private String email;

    @Column(nullable = false, length = 50)
    private String action;

    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 255)
    private String userAgent;

    @Column(nullable = false, length = 20)
    private String status;

    @Column(columnDefinition = "TEXT")
    private String details;

    protected AuditLogEntity() {}

    public AuditLogEntity(Instant eventTime, String email, String action, String ipAddress, String userAgent, String status, String details) {
        this.eventTime = eventTime;
        this.email = email;
        this.action = action;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.status = status;
        this.details = details;
    }

    public Long getId() { return id; }
    public Instant getEventTime() { return eventTime; }
    public String getEmail() { return email; }
    public String getAction() { return action; }
    public String getIpAddress() { return ipAddress; }
    public String getUserAgent() { return userAgent; }
    public String getStatus() { return status; }
    public String getDetails() { return details; }
}
