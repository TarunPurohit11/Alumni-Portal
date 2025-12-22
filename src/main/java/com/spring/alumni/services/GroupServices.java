package com.spring.alumni.services;

import com.spring.alumni.entities.Group;
import com.spring.alumni.entities.User;
import com.spring.alumni.entities.type.Role;
import com.spring.alumni.repositories.GroupRepository;
import com.spring.alumni.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class GroupServices {

    private final GroupRepository groupRepository;
    private final UserRepository userRepository;

    public Page<Group> getAllGroups(int page, int size) {
        Pageable pageable = PageRequest.of(page,size);
        return groupRepository.findAll(pageable);
    }

    public Page<Group> getJoinedGroups(int page, int size, String username) {
        User user = userRepository.findByUsername(username).orElseThrow();
        Pageable pageable = PageRequest.of(page,size);
        return groupRepository.findByMembers_Id(user.getId(),pageable);
    }

    public Map<String, Boolean> getAccessStatus(String username, Long groupId) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Group group = groupRepository.findById(groupId)
                .orElseThrow(() -> new RuntimeException("Group not found"));

        // Admins have full access, no assessment
        if (user.getRole() == Role.ADMIN) {
            return Map.of("allowed", true, "requireAssessment", false);
        }

        boolean isMember = group.getMembers().stream()
                .anyMatch(u -> u.getId().equals(user.getId()));

        if (isMember) {
            // Members have full access
            return Map.of("allowed", true, "requireAssessment", false);
        } else {
            // Non-members are "allowed" to proceed, but MUST take the assessment
            return Map.of("allowed", true, "requireAssessment", true);
        }
    }

    public Group getGroupById(Long groupId) {
        return groupRepository.findById(groupId)
                .orElseThrow(() -> new RuntimeException("Group not found"));
    }

    public String joinGroup(Long groupId, String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Group group = groupRepository.findById(groupId)
                .orElseThrow(() -> new RuntimeException("Group not found"));

        // Check if already a member
        boolean isMember = group.getMembers().stream()
                .anyMatch(u -> u.getId().equals(user.getId()));

        if (isMember) {
            return "Already a member";
        }

        // Add user to group
        group.getMembers().add(user);
        groupRepository.save(group);

        return "Joined group successfully";
    }

}
