package com.rf.labrex.exception;

public class NotFoundException extends RuntimeException{
   public NotFoundException(String dType){
        super(dType+" bulunamadi. Tekrar Dene ...");
    }
}
