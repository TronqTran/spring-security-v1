package com.vn.springsecurity.model;

import com.vn.springsecurity.enums.Role;
import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "_user")
public class User {
    @Id
    @GeneratedValue
    private Long id;

    @Column(unique = true)
    private String email;

    private String firstName;

    private String lastName;

    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    private String provider;

    private String providerId;
}
