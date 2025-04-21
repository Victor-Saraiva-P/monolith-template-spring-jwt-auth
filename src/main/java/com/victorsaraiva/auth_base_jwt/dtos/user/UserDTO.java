package com.victorsaraiva.auth_base_jwt.dtos.user;

import com.victorsaraiva.auth_base_jwt.models.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {
    private UUID id;

    private String username;

    private String email;

    private Role role = Role.USER; // valor padrão
}
