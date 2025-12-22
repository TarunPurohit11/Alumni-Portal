package com.spring.alumni.entities;

import com.spring.alumni.entities.type.Status;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "tech_groups")  // changed from "groups" to "tech_groups"
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Group {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Group name / title
    @Column(nullable = false, unique = true)
    private String title;

    // Short description about the group
    @Column(length = 500)
    private String description;

    // Optional longer content / details
    @Column(length = 2000)
    private String content;

    // Optional banner image URL
    private String imageUrl;

    // Date when the group was created
    private LocalDateTime createdAt = LocalDateTime.now();

    // Status (ACTIVE / INACTIVE / ARCHIVED)
    @Enumerated(EnumType.STRING)
    private Status status = Status.ACTIVE;

    // Users who joined the group
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_tech_groups",   // changed join table name
            joinColumns = @JoinColumn(name = "group_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id")
    )
    private Set<User> members = new HashSet<>();
}
