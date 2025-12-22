package com.spring.alumni.repositories;

import com.spring.alumni.entities.Message;
import com.spring.alumni.dtos.ConversationDTO;
import com.spring.alumni.entities.User;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface MessageRepository extends JpaRepository<Message, Long> {

    @Query("""
        SELECT m FROM Message m
        WHERE (m.sender.id = :u1 AND m.receiver.id = :u2)
           OR (m.sender.id = :u2 AND m.receiver.id = :u1)
        ORDER BY m.sentAt ASC
    """)
    List<Message> getChat(@Param("u1") Long u1, @Param("u2") Long u2);

    @Query("""
        SELECT new com.spring.alumni.dtos.ConversationDTO(
            CASE WHEN m.sender.id = :uid THEN m.receiver.id ELSE m.sender.id END,
            CASE WHEN m.sender.id = :uid THEN m.receiver.name ELSE m.sender.name END,
            CASE WHEN m.sender.id = :uid THEN m.receiver.profilePic ELSE m.sender.profilePic END,
            m.content,
            m.sentAt
        )
        FROM Message m
        WHERE m.id IN (
            SELECT MAX(m2.id) FROM Message m2
            WHERE m2.sender.id = :uid OR m2.receiver.id = :uid
            GROUP BY
                CASE WHEN m2.sender.id = :uid THEN m2.receiver.id ELSE m2.sender.id END
        )
        ORDER BY m.sentAt DESC
    """)
    List<ConversationDTO> getInbox(@Param("uid") Long userId);

    Long countByReceiverAndReadStatusFalse(User user);
}
