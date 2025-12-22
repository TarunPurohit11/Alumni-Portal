package com.spring.alumni.services.gemini;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.List;
import java.util.Map;

@Service
public class GeminiService {

    private final WebClient webClient;

    @Value("${gemini.api.key}")
    private String apiKey;

    public GeminiService(@Value("${google.gemini.url}") String apiUrl) {
        this.webClient = WebClient.builder()
                .baseUrl(apiUrl)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    // ✅ STRING RETURN (blocking)
    public String generateAssessment(String groupName, String description) {

        String prompt = """
        You are an exam question generator.

        Generate exactly 5 multiple choice questions.
        Difficulty level: MEDIUM

        Group Name: %s
        Group Description: %s

        Rules:
        - 4 options per question
        - One correct option
        - Output ONLY valid JSON in this format:
        {
          "questions": [
            {
              "question": "The question text",
              "options": {"A": "Choice 1", "B": "Choice 2", "C": "Choice 3", "D": "Choice 4"},
              "correctAnswer": "A"
            }
          ]
        }
        """.formatted(groupName, description);

        Map<String, Object> requestBody = Map.of(
                "contents", List.of(
                        Map.of("parts", List.of(
                                Map.of("text", prompt)
                        ))
                )
        );

        try {
            Map response = webClient.post()
                    .uri(uriBuilder -> uriBuilder
                            // ✅ Stable & available model
                            .path("/v1beta/models/gemini-2.5-flash-lite:generateContent")
                            .queryParam("key", apiKey)
                            .build())
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block(); // 🔴 blocking here by design

            return extractJson(response);

        } catch (WebClientResponseException e) {
            return "Gemini API Error: " + e.getStatusCode()
                    + " - " + e.getResponseBodyAsString();
        } catch (Exception e) {
            return "Unexpected error: " + e.getMessage();
        }
    }

    // Same extraction logic
    private String extractJson(Map body) {
        List<Map<String, Object>> candidates =
                (List<Map<String, Object>>) body.get("candidates");

        if (candidates == null || candidates.isEmpty()) {
            return "{}"; // empty JSON
        }

        Map<String, Object> content =
                (Map<String, Object>) candidates.get(0).get("content");

        if (content == null) return "{}";

        List<Map<String, Object>> parts =
                (List<Map<String, Object>>) content.get("parts");

        if (parts == null || parts.isEmpty()) return "{}";

        String text = parts.get(0).get("text").toString();

        System.out.println("data: " + text);
        // ✅ Strip triple backticks
        return text.replaceAll("(?s)```json|```", "").trim();
    }

}
