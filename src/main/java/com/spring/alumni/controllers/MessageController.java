package com.spring.alumni.controllers;

import com.spring.alumni.dtos.*;
import com.spring.alumni.entities.User;
import com.spring.alumni.services.MessageService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/messages")
@RequiredArgsConstructor
public class MessageController {

    private final MessageService messageService;

    @PostMapping("/send")
    public void sendMessage(
            @AuthenticationPrincipal User user,
            @RequestBody SendMessageDTO dto
    ) {
        messageService.sendMessage(user, dto);
    }

    @GetMapping("/chat/{userId}")
    public List<?> getChat(
            @AuthenticationPrincipal User user,
            @PathVariable Long userId
    ) {
        return messageService.getChat(user.getId(), userId);
    }

    @GetMapping("/inbox")
    public List<ConversationDTO> inbox(
            @AuthenticationPrincipal User user
    ) {
        return messageService.getInbox(user.getId());
    }
    @GetMapping("/unread-count")
    public Long getUnreadCount(@AuthenticationPrincipal User user) {
        return messageService.countByReceiverAndReadStatusFalse(user);
    }

}
