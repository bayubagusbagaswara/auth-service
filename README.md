
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
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "refresh_token": "secure-random-token",
  "user": {
    "username": "testuser",
    "fullName": "Test User",
    "branchName": "JKT-HO",
    "status": "ACTIVE",
    "groupLevel": "Support User",
    "lastLogin": null,
    "menus": [
      "compliance_InquiryLiquidation",
      "compliance_EditBreachDays"
    ]
  }
}

```