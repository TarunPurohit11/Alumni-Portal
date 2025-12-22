package com.spring.alumni.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AssessmentResponse {
    private boolean passed;
    private int score;
}
