#! /bin/bash
set -x

# 根证书
openssl ecparam -genkey -name secp384r1 -out private/root-sk.pem -noout
openssl req -new -out request/root.csr -key private/root-sk.pem -sha384 \
    -subj "/C=CN/ST=Hubei/L=Wuhan/O=WHU/OU=SCSE/CN=RayoNicks"
openssl x509 -req -in request/root.csr -signkey private/root-sk.pem -out cert/root.crt -sha384 \
    -extfile ../openssl.conf -extensions oniv_ca

# 代理CA证书
openssl ecparam -genkey -name secp384r1 -out private/proxy-sk.pem -noout
openssl req -new -out request/proxy.csr -key private/proxy-sk.pem -sha384 \
    -subj "/C=CN/ST=Hubei/L=Wuhan/O=WHU/OU=SCSE/CN=Proxy"
openssl x509 -req -in request/proxy.csr -CA cert/root.crt -CAkey private/root-sk.pem -CAcreateserial \
    -out cert/proxy.crt -sha384 -extfile ../openssl.conf -extensions oniv_ca

# 客户机1证书
openssl ecparam -genkey -name secp384r1 -out private/guest1-sk.pem -noout
openssl req -new -out request/guest1.csr -key private/guest1-sk.pem -sha384 \
    -subj "/C=CN/ST=Hubei/L=Wuhan/O=WHU/OU=SCSE/CN=guest1"
openssl x509 -req -in request/guest1.csr -CA cert/root.crt -CAkey private/root-sk.pem \
    -out cert/guest1-2nd.crt -sha384 -extfile ../openssl.conf -extensions oniv_guest
openssl x509 -req -in request/guest1.csr -CA cert/proxy.crt -CAkey private/proxy-sk.pem -CAcreateserial \
    -out cert/guest1-3rd.crt -sha384 -extfile ../openssl.conf -extensions oniv_guest

# 客户机2证书
openssl ecparam -genkey -name secp384r1 -out private/guest2-sk.pem -noout
openssl req -new -out request/guest2.csr -key private/guest2-sk.pem -sha384 \
    -subj "/C=CN/ST=Hubei/L=Wuhan/O=WHU/OU=SCSE/CN=guest2"
openssl x509 -req -in request/guest2.csr -CA cert/root.crt -CAkey private/root-sk.pem \
    -out cert/guest2-2nd.crt -sha384 -extfile ../openssl.conf -extensions oniv_guest
openssl x509 -req -in request/guest2.csr -CA cert/proxy.crt -CAkey private/proxy-sk.pem \
    -out cert/guest2-3rd.crt -sha384 -extfile ../openssl.conf -extensions oniv_guest

# 客户机3证书
openssl ecparam -genkey -name secp384r1 -out private/guest3-sk.pem -noout
openssl req -new -out request/guest3.csr -key private/guest3-sk.pem -sha384 \
    -subj "/C=CN/ST=Hubei/L=Wuhan/O=WHU/OU=SCSE/CN=guest3"
openssl x509 -req -in request/guest3.csr -CA cert/root.crt -CAkey private/root-sk.pem \
    -out cert/guest3-2nd.crt -sha384 -extfile ../openssl.conf -extensions oniv_guest
openssl x509 -req -in request/guest3.csr -CA cert/proxy.crt -CAkey private/proxy-sk.pem \
    -out cert/guest3-3rd.crt -sha384 -extfile ../openssl.conf -extensions oniv_guest

# 合并根证书文件
cat cert/root.crt > cert/chain.crt
cat cert/proxy.crt >> cert/chain.crt
