package com.fptaptech.auth.domain;

import jakarta.persistence.*;

@Entity
@Table(name = "roles")
public class Role {

    public static final String STUDENT = "ROLE_STUDENT";
    public static final String LECTURER = "ROLE_LECTURER";
    public static final String ADMIN = "ROLE_ADMIN";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String name;

    protected Role() {}

    public Role(String name) {
        this.name = name;
    }

    public Long getId() { return id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}
