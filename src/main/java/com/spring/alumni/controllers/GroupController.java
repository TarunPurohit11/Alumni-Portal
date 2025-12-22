package com.spring.alumni.controllers;

import com.spring.alumni.entities.Group;
import com.spring.alumni.services.GroupServices;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api/groups")
@RequiredArgsConstructor
@CrossOrigin
public class GroupController {

    private final GroupServices groupServices;

    @GetMapping("/all")
    public Page<Group> getGroups(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "3") int size){
        return groupServices.getAllGroups(page, size);
    }

    @GetMapping("/user/{username}")
    public Page<Group> getMyGroups(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "3") int size,
            @PathVariable String username){
        System.out.println("username: "+username);
        return groupServices.getJoinedGroups(page, size,username);
    }

    @GetMapping("/{groupId}/access")
    public ResponseEntity<?> checkAccess(@PathVariable Long groupId, Principal principal) {
        // Call the updated service method
        Map<String, Boolean> accessStatus = groupServices.getAccessStatus(principal.getName(), groupId);

        return ResponseEntity.ok(accessStatus);
    }

    @GetMapping("/{groupId}")
    public ResponseEntity<?> getGroup(@PathVariable Long groupId) {
        try {
            Group group = groupServices.getGroupById(groupId);
            return ResponseEntity.ok(group);
        } catch (RuntimeException e) {
            return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/{groupId}/join")
    public ResponseEntity<?> joinGroup(@PathVariable Long groupId, Principal principal) {
        try {
            String message = groupServices.joinGroup(groupId, principal.getName());
            if (message.equals("Already a member")) {
                return ResponseEntity.badRequest().body(Map.of("message", message));
            }
            return ResponseEntity.ok(Map.of("message", message));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", e.getMessage()));
        }
    }


}
