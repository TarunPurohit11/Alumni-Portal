package com.spring.alumni.dtos;

import lombok.Data;

import java.time.LocalDate;

@Data
public class EventDTO {
    private String title;
    private String shortDescription;
    private String content;
    private LocalDate eventDate;
    private String imageUrl;
}