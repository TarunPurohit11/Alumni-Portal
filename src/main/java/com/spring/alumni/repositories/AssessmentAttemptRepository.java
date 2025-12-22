package com.spring.alumni.repositories;

import com.spring.alumni.entities.AssessmentAttempt;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AssessmentAttemptRepository
        extends JpaRepository<AssessmentAttempt, Long> {

    /*
     * Fetch latest attempt of a user for a group
     * Used for:
     * - checking pass/fail
     * - cooldown enforcement
     */
    Optional<AssessmentAttempt>
    findTopByUserIdAndGroupIdOrderByAttemptedAtDesc(
            Long userId,
            Long groupId
    );
}

