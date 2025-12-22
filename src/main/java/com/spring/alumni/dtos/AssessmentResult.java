package com.spring.alumni.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AssessmentResult {
    private boolean passed;
    private int score;
}
