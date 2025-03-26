package com.rf.labrex.config;

import com.rf.labrex.entity.BaseUser;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;


/*
bu sınıf yetkileri kontrol etmek için oluşturuldu
örneğin security kısmında rapor düzenleme işlemlerini worker yapabilir
ama sadece kendi işlemlerini yapabilmeli başkalarının raporunu düzenleyememeli
bunu @PreAuthorize anatosyonuyla yapabilirdik ama gerekli şartları daha rahat
yapmak için bu sınıfı oluşturdum
*
*/
@Configuration

public class QueryConfig {

    // giriş yapmış kullanıcıyı alıyoruz
    public BaseUser getAuthentication(){
        Authentication authentication= SecurityContextHolder.getContext().getAuthentication();
        BaseUser user =(BaseUser) authentication.getPrincipal();
        return user;
    }
    public boolean isAuthorized(BaseUser authenticate,BaseUser request){
        return authenticate.getId().equals(request.getId());
    }
}
