package com.spring.alumni.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

// src/main/java/com/spring/alumni/dtos/QuestionDTO.java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class QuestionDTO {
    private String question;
    private Map<String, String> options;
    private String correctAnswer; // Gemini will populate this (e.g., "A")
}