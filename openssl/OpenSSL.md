# 证书生成
1. 物理机使用私钥生成自签名的证书作为根证书
2. 虚拟机提供证书申请者信息（不包含密钥），物理机使用根证书签发虚拟机证书，将证书链返回给虚拟机
3. 虚拟机之间基于证书链进行身份验证和密钥协商

# 为物理机签发根证书
- 执行`openssl genrsa -out root.pem`，生成物理机私钥
- 执行`openssl req -new -out root.csr -key root.pem`，输入主体信息生成证书申请
- 执行`openssl x509 -req -in root.csr -signkey root.pem -out root.crt`，生成根证书

# 为虚拟机签发证书
1. 为客户机1申请证书
   - 执行`openssl genrsa -out guest1.pem`，生成客户机1私钥
   - 执行`openssl req -new -out guest1.csr -key guest1.pem`，输入主体信息生成证书申请
   - 执行`openssl x509 -req -in guest1.csr -CA root.crt -CAkey root.pem -CAcreateserial -out guest1.crt`，生成guest1证书
`

1. 为主机2申请证书
   - 执行`openssl genrsa -out guest2.pem`，生成客户机2私钥
   - 执行`openssl req -new -out guest2.csr -key guest2.pem`
   - 执行`openssl x509 -req -in guest2.csr -CA root.crt -CAkey root.pem -out guest2.crt`，不需要`-CAcreateserial`选项

3. 为主机3申请证书
   - 执行`openssl genrsa -out guest3.pem`，生成客户机3私钥
   - 执行`openssl req -new -out guest3.csr -key guest3.pem`
   - 执行`openssl x509 -req -in guest3.csr -CA root.crt -CAkey root.pem -out guest3.crt`

4. 为主机4申请证书
   - 执行`openssl genrsa -out guest4.pem`，生成客户机4私钥
   - 执行`openssl req -new -out guest4.csr -key guest4.pem`
   - 执行`openssl x509 -req -in guest4.csr -CA root.crt -CAkey root.pem -out guest4.crt`

5. 申请多级证书
   - 执行`openssl genrsa -out second.pem`，生成二级颁发机构的私钥
   - 执行`openssl req -new -out second.csr -key second.pem`
   - 执行`openssl x509 -req -in second.csr -CA root.crt -CAkey root.pem -out second.crt`
   - 执行`openssl genrsa -out third.pem`，生成三级用户私钥
   - 执行`openssl req -new -out third.csr -key third.pem`
   - 执行`openssl x509 -req -in third.csr -CA second.crt -CAkey second.pem -CAcreateserial -out third.crt`，使二级颁发机构为三级用户颁发证书

# 签名
## 直接签名
执行`openssl rsautl -sign -inkey guest1.pem -in root.srl -out guest1.sig`，使用`guest1.pem`中的私钥对`root.srl`中的数据进行签名

根据对`openssl-1.0.2g/apps/rsautl.c`中源代码的分析，签名操作主要通过使用`PEM_read_bio_PrivateKey()`解析私钥文件，使用`EVP_PKEY_get1_RSA()`转换RSA私钥和使用`RSA_private_encrypt()`进行签名完成

# 摘要签名
执行`openssl dgst -sha256 -sign guest1.pem -out guest1.sig root.srl`，使用`guest1.pem`中的私钥对`root.srl`中的数据进行摘要运算，然后再进行签名

摘要签名可以通过手动调用摘要算法进行签名然后借助直接签名的方式实现，也可以通过调用EVP相关函数实现，具体为调用`EVP_add_digest(EVP_sha256())`加载摘要算法，最终通过`EVP_DigestSignInit()`、`EVP_DigestSignUpdate()`和`EVP_DigestSignFinal`实现

# 验证证书
## 单级证书验证
执行`openssl verify -CAfile root.crt guest1.crt`以验证客户机1的证书

## 多级证书验证
执行`cat root.crt > chain.crt`和`cat second.crt >> chain.crt`以将两级颁发机构证书合并到同一个文件中，最后执行`openssl verify -CAfile chain.crt third.crt`验证三级用户的证书

## 源码分析
根据对`openssl-1.0.2g/apps/verify.c`中的源代码的分析，证书验证首先要读取证书链中的所有证书，这通过`X509_STORE_add_lookup()`、`X509_LOOKUP_load_file()`、`by_file_ctrl()`和`X509_load_cert_crl_file()`等一系列调用来将证书链加入到`cert_ctx`中，最终通过`X509_verify_cert()`实现证书验证

# 证书验签
## 直接验签
执行`openssl rsautl -verify -inkey guest1.crt -certin -in guest1.sig -out guest1.sig`使用证书验证签名

根据对`openssl-1.0.2g/apps/rsautl.c`中源代码的分析，验证操作主要通过使用`PEM_read_bio_X509_AUX()`加载证书、使用`X509_get_pubkey()`从证书中提取公钥和使用`RSA_public_decrypt()`验签完成

## 摘要验签
- 执行`openssl x509 -pubkey -noout -in guest1.crt > guest1.pub`从证书中提取公钥
- 执行`openssl dgst -sha256 -verify guest1.pub -signature guest1.sig root.srl`使用公钥验证签名

和摘要签名相反，摘要验签通过`EVP_DigestVerifyInit()`、`EVP_DigestVerifyUpdate()`和`EVP_DigestVerifyFinal()`实现

# 密钥协商
TLS 1.3中规定的有限域密钥协商算法`ffdhe2048`、`ffdhe3072`、`ffdhe4096`、`ffdhe6144`和`ffdhe8192`在OpenSSL 1.0.2g中未定义，因此需要使用椭圆曲线密钥协商算法——`secp384r1`和`secp521r1`。

通过`EC_KEY_new_by_curve_name()`生成密钥，然后通过`ECDH_compute_key()`计算共享密钥。

# 消息认证码
经过实验，OpenSSL 1.0.2g版本中只有AES-128-GCM-SHA256算法可以正常使用，其余的AEAD算法编码均存在一些问题，即使是同类别的AES-256-GCM-SHA384也存在问题。

# 公钥加密和解密
- 执行`openssl rsautl -encrypt -inkey guest1.crt -certin -in root.srl -out guest1.enc`使用证书进行加密
- 执行`openssl rsautl -decrypt -inkey guest1.pem -in guest1.enc`使用私钥进行解密

主要通过`RSA_public_encrypt()`和`RSA_private_decrypt()`实现

# 总结
1. 支持三种证书，分别：
   1. RSA-2048，证书签名算法可以使sha256、sha384和sha512
   2. secp384r1，证书签名算法sha384
   3. secp521r1，证书签名算法sha512
2. 支持两种密钥协商算法，分别：
   1. secp384r1
   2. secp521r1
3. 支持两种AEAD算法：
   1. AES_128_GCM_SHA256
   2. AED_128_CCM_SHA256


# 参考文档
[OpenSSL证书操作详解](https://www.cnblogs.com/zhi-leaf/p/11987394.html)

[openssl-genpkey](https://www.openssl.org/docs/manmaster/man1/openssl-genpkey.html)

[openssl-pkutl](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)

[有关AesGCM算法的一些总结](https://www.jianshu.com/p/c79dedb5c458)

[TLS 1.2/1.3 加密原理(AES-GCM + ECDHE-ECDSA/RSA)](https://blog.csdn.net/m0_37621078/article/details/106028622)