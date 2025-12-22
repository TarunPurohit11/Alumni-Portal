package com.spring.alumni.dtos;

import java.time.LocalDateTime;

public class InboxDTO {

    private Long messageId;
    private Long senderId;
    private String senderName;
    private String senderRole;
    private String subject;
    private String content;
    private Boolean read;
    private LocalDateTime sentAt;

    public InboxDTO(
            Long messageId,
            Long senderId,
            String senderName,
            String senderRole,
            String subject,
            String content,
            Boolean read,
            LocalDateTime sentAt
    ) {
        this.messageId = messageId;
        this.senderId = senderId;
        this.senderName = senderName;
        this.senderRole = senderRole;
        this.subject = subject;
        this.content = content;
        this.read = read;
        this.sentAt = sentAt;
    }
}
