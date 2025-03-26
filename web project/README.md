
# Laboratuvar Raporlama Backend


# Açıklama
 Bu sistem, laboratuvar çalışanlarının hastaların test sonuçlarını kaydetmelerine, güncellemelerine, raporlamalarına ve arşivlemelerine olanak tanır. Aynı zamanda sistem, yetkilendirilmiş kullanıcılara farklı erişim seviyeleri sunar, böylece her kullanıcı sadece yetkili olduğu alanlara erişebilir



## Özellikler

- **Kullanıcı Yetkilendirmesi**: Farklı yetkilendirme seviyelerine sahip kullanıcılar vardır. Yöneticiler, laboratuvar çalışanları ve hasta kullanıcıları arasında yetki farklılıkları bulunur.
  
- **Hasta Yönetimi**: Sisteme kayıtlı hastaların bilgilerini saklama, güncelleme ve silme işlemleri yapılabilir. Ayrıca hastalara ait raporları listeleme ve silme yetkisi vardır.

- **Laboratuvar Çalışanı Yönetimi**: Yöneticiler, laboratuvar çalışanlarının bilgilerini yönetebilir. Yeni çalışan ekleyebilir, var olanları güncelleyebilir ve silebilir.

- **Hastane Yönetimi**: Sistem yöneticileri, hastanelerin bilgilerini yönetebilir. Yeni hastane ekleyebilir, var olanları güncelleyebilir ve silebilir.

- **Raporlama**: Laboratuvar çalışanları, test sonuçlarını sisteme kaydedebilir, güncelleyebilir ve silebilir. Ayrıca hastaların test sonuçlarını listeleme ve belirli kriterlere göre sıralama yetkisi bulunur.

## API Yetki Rotaları

### HERKESE AÇIK

- `api/v1/auth/**`
- `api/v1/patient/save`

### SADECE ADMİN

- `api/v1/hospital/**`
- `api/v1/worker/**`
- `api/v1/report/search/{value}`

### ADMİN VE LABORANT

- `api/v1/patient/list`

### ADMİN VE HASTA

- `api/v1/patient/delete/{id}`

### SADECE LABORANT

- `api/v1/report/save/**`
- `api/v1/report/update/{id}`
- `api/v1/report/delete/{id}`
- `api/v1/report/list/worker/{workerId}`

### HASTA VE LABORANT

- `api/v1/report/list/patient/{patientId}`
- `api/v1/report/{id}`

- `api/v1/report/sort/patient/**`








  
## Bilgisayarınızda Çalıştırın

docker pull

```bash
  docker pull /labreport:latest
```

image id öğren
```bash
  docker images
```
*burada image id'sini al ilk 3 hanesini 
aşağıya yaz



Sunucuyu çalıştırın

```bash
  docker run -p8080:8080 {id}
```

## SWAGGER
  projeyi çalıştırdıktan sonra detaylı olarak apileri kullanmak isterseniz 
  http://localhost:8080/swagger-ui/index.html#/
bu linke tıklayın
  
## Kullanılan Teknolojiler

 Java,SpringBoot,Spring Security,Docker,MySql,swagger

 ## Admin şifre
    "identificationNumber" : "89649430676",
    "password" : "Ef123456789"
    

 

  
