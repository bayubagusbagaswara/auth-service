
```bash
auth-service/
├── jwt-keys/
│   ├── private.pem
│   └── public.pem
├── src/
├── pom.xml
└── .gitignore
```

Buka terminal pada folder project dan jalankan perintah berikut jika OpenSSL sudah tersedia:
```bash
mkdir jwt-keys

openssl genpkey -algorithm RSA `
  -pkeyopt rsa_keygen_bits:3072 `
  -out jwt-keys/private.pem

openssl pkey `
  -in jwt-keys/private.pem `
  -pubout `
  -out jwt-keys/public.pem
```

Perintah tersebut menghasilkan:
- private.pem — menandatangani JWT, hanya untuk auth-service.
- public.pem — memverifikasi tanda tangan JWT.

- Format private key yang dihasilkan adalah PKCS#8, sesuai pembacaan kunci Java yang akan kita gunakan.

# Response login

```json
{
  "httpStatus": 200,
  "code": "SUCCESS",
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiJ9...",
    "refresh_token": "secure-refresh-token",
    "user": {
      "username": "testuser",
      "fullName": "Test User",
      "branchName": "JKT-HO",
      "status": "ACTIVE",
      "groupLevel": "Support User",
      "lastLogin": null,
      "menus": [
        "compliance_InquiryLiquidation"
      ]
    }
  }
}
```

# Contoh request /me

```bash

const getCurrentUser = async (accessToken) => {
    const response = await axios.get(
        "http://localhost:8081/api/v1/auth/me",
        {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        }
    );

    return response.data;
};

```

# 4. Contoh penggunaan pada backend service
Misalnya, nanti pada billing-service, kita memiliki endpoint:

```java
@PreAuthorize("hasAuthority('compliance_InquiryLiquidation')")
@GetMapping("/liquidation")
public ResponseEntity<?> getLiquidation() {
    // Business logic
    return ResponseEntity.ok().build();
}
```

# Prinsip yang kita gunakan:
- Private Key (private.pem) hanya disimpan di server auth-service atau sistem pengelolaan secret yang aman. Digunakan untuk menandatangani JWT.
- Public Key (public.pem) digunakan untuk memverifikasi JWT. Dapat dipublikasikan melalui endpoint JWKS.
- Setiap environment menggunakan pasangan RSA Key sendiri.
- billing-service, core-service, dan hiport-service tidak perlu menyimpan Private Key milik Auth Service.

# Simpan Private Key dan Public Key
Jika server SIT menggunakan Windows, Anda bisa menyimpan RSA Key di folder:

```bash
D:\opt\custody\secrets\auth-service\
├── private.pem
└── public.pem
```

# Konfigurasi application-sit.yml
```yml
app:
  jwt:
    issuer: https://auth-sit.example.internal
    key-id: auth-sit-rsa-1
    private-key: D:/opt/custody/secrets/auth-service/private.pem
    public-key: D:/opt/custody/secrets/auth-service/public.pem
    access-token-expiration: 15m
    refresh-token-expiration: 7d
    audience:
      - auth-service
      - billing-service
      - core-service
      - hiport-service
```

## 1. Struktur folder pada Windows Server

Contohnya, pada masing-masing server:

```bash
D:\
└── opt\
    └── custody\
        ├── auth-service\
        │   └── auth-service.jar
        │
        └── secrets\
            └── auth-service\
                ├── private.pem
                └── public.pem
```

# Generate Private Key dan Public Key

Untuk membuat RSA Private Key dan Public Key pada Windows Server, kita bisa menggunakan OpenSSL. Cara ini sesuai dengan implementasi JwtConfig.java Anda yang menggunakan algoritma RS256, Private Key berformat PKCS#8, dan Public Key berformat X.509.

Saya sarankan menggunakan RSA 3072-bit.
1. Periksa apakah OpenSSL tersedia
Buka PowerShell pada Windows Server, kemudian jalankan:

```bash
openssl version
```

Jika berhasil, akan muncul versi OpenSSL, misalnya OpenSSL 3.x.x.

Jika muncul pesan openssl is not recognized, berarti OpenSSL belum tersedia di PATH. Anda perlu menggunakan instalasi OpenSSL yang disediakan atau disetujui oleh tim infrastruktur.

2. Buat folder penyimpanan RSA Key
Misalnya, kita menggunakan lokasi SIT yang sudah Anda tentukan:

```bash
D:\opt\custody\secrets\auth-service\
```
Jalankan PowerShell:
```bash
New-Item -ItemType Directory -Force `
-Path "D:\opt\custody\secrets\auth-service"
```

Kemudian masuk ke folder tersebut:
```bash
Set-Location "D:\opt\custody\secrets\auth-service"
```

3. Generate RSA Private Key
Jalankan:
```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:3072 
```
Perintah tersebut akan menghasilkan file:
```bash
private.pem
```

File ini digunakan oleh `auth-service` untuk menandatangani JWT.

Format awal file akan terlihat seperti:

```bash
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

Itulah format `PKCS#8` yang dibaca oleh `JwtConfig.java` Anda.

4. Generate RSA Public Key
Setelah Private Key berhasil dibuat, jalankan:
```bash
openssl pkey -in private.pem -pubout -out public.pem 
```

Perintah ini mengekstrak Public Key dari Private Key sebelumnya.

Format file:

```bash
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
```

Sekarang folder Anda berisi:
```bash
D:\opt\custody\secrets\auth-service\
├── private.pem
└── public.pem
```

Jangan menjalankan perintah generate private key ulang jika sudah ada key yang digunakan, karena bisa menimpa pasangan key dan menyebabkan JWT yang masih aktif gagal diverifikasi.

5. Verifikasi pasangan RSA Key
Pertama, periksa apakah Private Key valid:
```bash
openssl pkey -in private.pem -check -noout 
```
Kemudian periksa Public Key:
```bash
openssl pkey -pubin -in public.pem -text -noout
```

Untuk memastikan keduanya memang satu pasangan, jalankan:

```bash
openssl pkey -in private.pem -pubout -outform DER |
    openssl dgst -sha256
```

Lalu:

```bash
openssl pkey -pubin -in public.pem -pubout -outform DER |
    openssl dgst -sha256
```

**Kedua nilai SHA-256 harus sama**. Nilai tersebut merupakan fingerprint dari representasi public key, bukan Private Key.

6. Atur izin akses pada Windows Server
Ini penting, terutama untuk file private.pem.

Misalnya, service dijalankan menggunakan akun Windows khusus DOMAIN\svc-auth. Tim infrastruktur dapat mengatur NTFS permissions agar hanya akun tersebut, SYSTEM, dan administrator yang berwenang dapat membaca Private Key.

Contoh PowerShell untuk folder khusus yang baru dibuat:

```bash
$folder = "D:\opt\custody\secrets\auth-service"

icacls $folder /inheritance:r

icacls $folder /grant:r `
  "DOMAIN\svc-auth:(OI)(CI)RX" `
  "SYSTEM:(OI)(CI)F" `
  "BUILTIN\Administrators:(OI)(CI)F"
```
Ganti DOMAIN\svc-auth dengan akun yang benar-benar menjalankan Auth Service. Pastikan izin administrator dan akun layanan sudah benar sebelum menghapus inheritance; jika tidak, aplikasi atau administrator bisa kehilangan akses ke folder.

Untuk Production, sebaiknya pengaturan ini dikerjakan bersama tim infrastruktur.

7. Sesuaikan application-sit.yml
Setelah kedua file berhasil dibuat, gunakan konfigurasi berikut:

```bash
app:
  jwt:
    issuer: https://auth-sit.example.internal
    key-id: auth-sit-rsa-1
    private-key: D:/opt/custody/secrets/auth-service/private.pem
    public-key: D:/opt/custody/secrets/auth-service/public.pem
    access-token-expiration: 15m
    refresh-token-expiration: 7d
    audience:
      - auth-service
      - billing-service
      - core-service
      - hiport-service
```

Dengan begitu, kode JwtConfig.java yang sudah Anda buat akan membaca file langsung dari lokasi tersebut.

8. Bagaimana untuk UAT dan Production?
Lakukan langkah yang sama secara terpisah pada masing-masing Windows Server. 

| Environment	          | Private Key                      | 	Public Key                                             |
|:----------------------|:---------------------------------|:--------------------------------------------------------|
| SIT                   | 	Generate khusus SIT             | Berpasangan dengan Private Key SIT                      |
| UAT	                  | Generate khusus UAT	             | Berpasangan dengan Private Key UAT                      |
| Production	           | Generate khusus                  | Production	Berpasangan dengan Private Key Production    |

Jangan menyalin private.pem dari SIT ke UAT atau Production.

Kesimpulan: Untuk menghasilkan kedua key tersebut, inti perintahnya hanya:

```bash
# Generate RSA Private Key 3072-bit
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:3072

# Generate Public Key dari Private Key
openssl pkey -in private.pem -pubout -out public.pem
```