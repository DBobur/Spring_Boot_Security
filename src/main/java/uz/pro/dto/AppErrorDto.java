package uz.pro.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class AppErrorDto {
    private String errorPath;
    private String errorMessage;
    private Integer errorCode;
    private LocalDateTime timeStamp;
}
