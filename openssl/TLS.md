# 参考TLS的内容
## 密钥协商算法
### 椭圆曲线密钥协商
TLS 1.3中的椭圆曲线密钥协商算法椭圆曲线群：
| 算法名称 | 值 |
|--|--|
| secp256r1 | 0x0017 |
| secp384r1 | 0x0018 |
| secp521r1 | 0x0019 |
| x25519 | 0x001D |
| x448 | 0x001E |

### 有限域密钥协商
| 算法名称 | 值 |
|--|--|
| ffdhe2048 | 0x0100 |
| ffdhe3072 | 0x0101 |
| ffdhe4096 | 0x0102 |
| ffdhe6144 | 0x0103 |
| ffdhe8192 | 0x0104 |

## 签名算法
| 算法名称 | 值 |
|--|--|
| rsa_pkcs1_sha256 | 0x0401 |
| rsa_pkcs1_sha384 | 0x0501 |
| rsa_pkcs1_sha512 | 0x0601 |
| ecdsa_secp256r1_sha256 | 0x0403 |
| ecdsa_secp384r1_sha384 | 0x0503 |
| ecdsa_secp521r1_sha512 | 0x0603 |
| rsa_pss_rsae_sha256 | 0x0804 |
| rsa_pss_rsae_sha384 | 0x0805 |
| rsa_pss_rsae_sha512 | 0x0806 |
| ed25519 | 0x0807 |
| ed448 | 0x0808 |
| rsa_pss_pss_sha256 | 0x0809 |
| rsa_pss_pss_sha384 | 0x080a |
| rsa_pss_pss_sha512 | 0x080b |
| rsa_pkcs1_sha1 | 0x0201 |
| ecdsa_sha1 | 0x0203 |

## 加密算法
TLS 1.3中的加密套件包括：
| 算法名称 | 值 |
|--|--|
| TLS_AES_128_GCM_SHA256 | {0x13,0x01} |
| TLS_AES_256_GCM_SHA384 | {0x13,0x02} |
| TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
| TLS_AES_128_CCM_SHA256 | {0x13,0x04} |
| TLS_AES_128_CCM_8_SHA256 | {0x13,0x05} |
