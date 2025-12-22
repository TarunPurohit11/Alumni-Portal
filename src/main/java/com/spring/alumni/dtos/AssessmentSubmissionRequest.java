package com.spring.alumni.dtos;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class AssessmentSubmissionRequest {
    private Map<Integer, String> answers; // e.g., {0: "A", 1: "C"}
    private List<QuestionDTO> questions;   // The original list with correct answers
}