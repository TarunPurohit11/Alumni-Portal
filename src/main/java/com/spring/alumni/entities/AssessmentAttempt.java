package com.spring.alumni.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(
        indexes = {
                @Index(name = "idx_attempt_user_group", columnList = "user_id, group_id"),
                @Index(name = "idx_attempt_time", columnList = "attemptedAt")
        }
)
public class AssessmentAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /* Who attempted the test */
    @ManyToOne(optional = false)
    private User user;

    /* Which group assessment */
    @ManyToOne(optional = false)
    private Group group;

    /* Score obtained */
    private int score;

    /* Did user pass? */
    private boolean passed;

    /* Attempt timestamp */
    @Column(nullable = false)
    private LocalDateTime attemptedAt;

    /* Retry allowed after this time (null if passed) */
    private LocalDateTime nextAllowedAttempt;
}

