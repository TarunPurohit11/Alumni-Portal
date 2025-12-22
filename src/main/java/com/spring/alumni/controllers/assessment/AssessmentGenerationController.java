package com.spring.alumni.controllers.assessment;

import com.spring.alumni.dtos.AssessmentResponse;
import com.spring.alumni.dtos.AssessmentSubmissionRequest;
import com.spring.alumni.dtos.QuestionDTO;
import com.spring.alumni.entities.Group;
import com.spring.alumni.entities.User;
import com.spring.alumni.repositories.GroupRepository;
import com.spring.alumni.services.gemini.GeminiService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/assessment")
@RequiredArgsConstructor
public class AssessmentGenerationController {

    private final GeminiService geminiService;
    private final GroupRepository groupRepository;

    @GetMapping("/generate/{groupId}")
    public String generateTest(@PathVariable Long groupId) {
        Group group = groupRepository.findById(groupId)
                .orElseThrow(() -> new RuntimeException("Group not found"));
        System.out.println("Group:"+ group);
        return geminiService.generateAssessment(
                group.getTitle(),
                group.getDescription()
        );
    }

    @PostMapping("/submit/{groupId}")
    public ResponseEntity<?> submitTest(
            @PathVariable Long groupId,
            @RequestBody AssessmentSubmissionRequest request,
            @AuthenticationPrincipal User user) {

        Group group = groupRepository.findById(groupId)
                .orElseThrow(() -> new RuntimeException("Group not found"));

        List<QuestionDTO> questions = request.getQuestions();
        Map<Integer, String> userAnswers = request.getAnswers();

        int correctCount = 0;
        for (int i = 0; i < ((java.util.List<?>) questions).size(); i++) {
            String correctAns = questions.get(i).getCorrectAnswer();
            String userAns = userAnswers.get(i);

            if (correctAns != null && correctAns.equalsIgnoreCase(userAns)) {
                correctCount++;
            }
        }

        int score = (correctCount * 100) / questions.size();
        boolean passed = score >= 70;

        if (passed) {
            // Add user to the ManyToMany relationship
            group.getMembers().add(user);
            groupRepository.save(group);
        }

        return ResponseEntity.ok(new AssessmentResponse(passed, score));
    }
}