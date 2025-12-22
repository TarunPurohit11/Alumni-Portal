package com.spring.alumni.dtos;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AdminActionResponseDTO {

    private boolean success;
    private String message;
    private AdminUserResponseDTO user;
}