package com.rishu.springsecurity.resources;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldResource {

    @GetMapping("/hello-world")
    // local CORS configuration
   // @CrossOrigin("http://our-own-client-origin")
    public String helloWorld(){
        return "Hello";
    }


}
