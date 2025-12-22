package com.spring.alumni.dtos;

import lombok.Data;

@Data
public class ChatMessageDTO {
    private Long senderId;
    private Long receiverId;
    private String content;
}
