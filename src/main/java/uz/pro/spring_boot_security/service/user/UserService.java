package uz.pro.spring_boot_security.service.user;

import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import uz.pro.spring_boot_security.dto.TokenRequest;
import uz.pro.spring_boot_security.entity.UserEntity;
import uz.pro.spring_boot_security.entity.UserRole;
import uz.pro.spring_boot_security.repository.UserRepository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    public UserEntity save(UserEntity userEntity){
        //UserEntity userEntity = modelMapper.map(request, UserEntity.class);
        userEntity.setPassword(passwordEncoder.encode(userEntity.getPassword()));
        userEntity.setRoles(List.of(UserRole.USER,UserRole.ADMIN));
        UserEntity save = userRepository.save(userEntity);
        return save;
    }
}
