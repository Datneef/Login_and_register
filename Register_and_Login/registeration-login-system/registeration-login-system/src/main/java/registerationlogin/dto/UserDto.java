package registerationlogin.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserDto {

    private Long id;
    @NotEmpty
    private String name;
    @NotEmpty(message = "Email không được để trống")
    @Email
    private String email;
    @NotEmpty(message = "Password không được để trống")
    private String password;

}
