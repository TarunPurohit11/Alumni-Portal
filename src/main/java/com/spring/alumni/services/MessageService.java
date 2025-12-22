package com.spring.alumni.services;

import com.spring.alumni.dtos.*;
import com.spring.alumni.entities.*;
import com.spring.alumni.repositories.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class MessageService {

    private final MessageRepository messageRepo;
    private final UserRepository userRepo;

    public void sendMessage(User sender, SendMessageDTO dto) {
        User receiver = userRepo.findById(dto.getReceiverId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        Message msg = Message.builder()
                .sender(sender)
                .receiver(receiver)
                .content(dto.getContent())
                .sentAt(LocalDateTime.now())
                .build();

        messageRepo.save(msg);
    }

    public List<Message> getChat(Long u1, Long u2) {
        return messageRepo.getChat(u1, u2);
    }

    public List<ConversationDTO> getInbox(Long userId) {
        return messageRepo.getInbox(userId);
    }

    public Long countByReceiverAndReadStatusFalse(User user) {
        return messageRepo.countByReceiverAndReadStatusFalse(user);
    }
}
