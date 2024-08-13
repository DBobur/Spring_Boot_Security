package uz.pro.spring_boot_security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class AppErrorDto {
    private String errorPath;
    private String errorMessage;
    private Integer errorCode;
    private LocalDateTime timeStamp;
}
