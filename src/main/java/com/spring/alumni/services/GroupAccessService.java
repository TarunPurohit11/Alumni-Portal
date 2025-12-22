package com.spring.alumni.services;

import com.spring.alumni.dtos.GroupAccessResponse;
import com.spring.alumni.entities.User;
import com.spring.alumni.repositories.AssessmentAttemptRepository;
import com.spring.alumni.repositories.GroupMembershipRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
@Service
@RequiredArgsConstructor
public class GroupAccessService {

    private final GroupMembershipRepository membershipRepo;
    private final AssessmentAttemptRepository attemptRepo;

    public GroupAccessResponse checkAccess(User user, Long groupId) {

        /* Step 1: Already member? */
        if (membershipRepo.existsByUserIdAndGroupId(user.getId(), groupId)) {
            return GroupAccessResponse.allowed();
        }

        var lastAttemptOpt =
                attemptRepo.findTopByUserIdAndGroupIdOrderByAttemptedAtDesc(
                        user.getId(), groupId);

        /* Step 2: No attempt yet */
        if (lastAttemptOpt.isEmpty()) {
            return GroupAccessResponse.requireAssessment();
        }

        var lastAttempt = lastAttemptOpt.get();

        /* Step 3: Passed previously */
        if (lastAttempt.isPassed()) {
            return GroupAccessResponse.allowed();
        }

        /* Step 4: Cooldown check (SAFE) */
        LocalDateTime nextRetry = lastAttempt.getNextAllowedAttempt();

        if (nextRetry != null && LocalDateTime.now().isBefore(nextRetry)) {
            return GroupAccessResponse.cooldown(nextRetry);
        }

        /* Step 5: Can retry assessment */
        return GroupAccessResponse.requireAssessment();
    }

}
