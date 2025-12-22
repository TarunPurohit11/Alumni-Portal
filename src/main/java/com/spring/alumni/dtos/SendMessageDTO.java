package com.spring.alumni.dtos;

import lombok.Data;

@Data
public class SendMessageDTO {
    private Long receiverId;
    private String content;
}

