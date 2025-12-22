package com.spring.alumni.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.spring.alumni.entities.type.AuthProviderType;
import com.spring.alumni.entities.type.Role;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "app_user")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @JsonIgnore
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    private String providerId;

    @Enumerated(EnumType.STRING)
    private AuthProviderType providerType;

    @Column(nullable = false)
    private String name;

    private String profilePic;

    private String title;
    private String company;

    private String course;
    private Integer year;

    private String city;

    @Column(length = 1000)
    private String about;

    @ElementCollection(fetch = FetchType.LAZY)
    private List<String> skills;

    /* ===== SECURITY FLAGS ===== */

    @Column(nullable = false)
    private boolean enabled = true;

    private boolean accountLocked = false;

    /* ===== UserDetails ===== */

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> "ROLE_" + role.name());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !accountLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}