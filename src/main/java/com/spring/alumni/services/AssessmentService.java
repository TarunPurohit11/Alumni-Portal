package com.spring.alumni.services;

import com.spring.alumni.dtos.AssessmentResult;
import com.spring.alumni.dtos.AssessmentSubmissionRequest;
import com.spring.alumni.entities.AssessmentAttempt;
import com.spring.alumni.entities.Group;
import com.spring.alumni.entities.GroupMembership;
import com.spring.alumni.entities.User;
import com.spring.alumni.repositories.AssessmentAttemptRepository;
import com.spring.alumni.repositories.GroupMembershipRepository;
import com.spring.alumni.repositories.GroupRepository;
import com.spring.alumni.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
@Service
@RequiredArgsConstructor
public class AssessmentService {

    private final AssessmentAttemptRepository attemptRepo;
    private final GroupRepository groupRepository;

    @Transactional
    public AssessmentResult processAndEnroll(User user, Long groupId, AssessmentSubmissionRequest request) {
        int totalQuestions = request.getQuestions().size();
        int correctCount = 0;

        // 1. Calculate Score
        for (int i = 0; i < totalQuestions; i++) {
            String userAnswer = request.getAnswers().get(i);
            String correctAnswer = request.getQuestions().get(i).getCorrectAnswer();

            if (userAnswer != null && userAnswer.equalsIgnoreCase(correctAnswer)) {
                correctCount++;
            }
        }

        int scorePercentage = (totalQuestions > 0) ? (correctCount * 100) / totalQuestions : 0;
        boolean passed = scorePercentage >= 70; // Passing threshold 70%

        // 2. Save the Attempt
        AssessmentAttempt attempt = AssessmentAttempt.builder()
                .user(user)
                .group(groupRepository.getReferenceById(groupId))
                .score(scorePercentage)
                .passed(passed)
                .attemptedAt(LocalDateTime.now())
                .nextAllowedAttempt(passed ? null : LocalDateTime.now().plusDays(1))
                .build();
        attemptRepo.save(attempt);

        // 3. Add to ManyToMany Relationship if passed
        if (passed) {
            Group group = groupRepository.findById(groupId)
                    .orElseThrow(() -> new RuntimeException("Group not found"));
            group.getMembers().add(user);
            groupRepository.save(group);
        }

        return new AssessmentResult(passed, scorePercentage);
    }
}