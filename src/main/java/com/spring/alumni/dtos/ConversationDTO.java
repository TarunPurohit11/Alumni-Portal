package com.spring.alumni.dtos;

import lombok.*;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
public class ConversationDTO {
    private Long userId;
    private String name;
    private String profilePic;
    private String lastMessage;
    private LocalDateTime lastMessageTime;
}

