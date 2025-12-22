package com.spring.alumni.dtos;

import lombok.Data;

@Data
public class AnnouncementDTO {
    private String title;
    private String shortDescription;
    private String content;
    private String imageUrl;
}
