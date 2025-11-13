package com.spring.alumni.exceptionHandler;

import lombok.Data;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

@Data
public class ApiError {
    private LocalDateTime timeStamp;
    private String error;
    private HttpStatus status;

    public ApiError(){
        this.timeStamp = LocalDateTime.now();
    }
    public ApiError(String error,HttpStatus status){
        this();
        this.error = error;
        this.status = status;
    }

}
