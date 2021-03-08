#ifndef _ONIV_H_
#define _ONIV_H_

#include <cstring>
#include <initializer_list>
#include <mutex>
#include <string>
#include <vector>

#include <netinet/in.h>

#include "onivglobal.h"

using std::initializer_list;
using std::mutex;
using std::string;
using std::vector;

enum class OnivPacketType : uint16_t
{
    UNKNOWN,
    TUN_KA_REQ,
    TUN_KA_RES,
    TUN_KA_FIN,
    TUN_KA_FAIL,
    TUN_IV_ERR,
    ONIV_RECORD,
    LNK_KA_REQ,
    LNK_KA_RES,
    LNK_KA_FIN,
    LNK_KA_FAIL,
    LNK_IV_ERR,
};

enum class OnivPacketFlag : uint16_t
{
    NONE = 0x0000,
    UPD_ID = 0x0001,
    UPD_SEND = 0x0002,
    UPD_RECV = 0x0004,
    ACK_ID = 0x00010,
    ACK_SEND = 0x0020,
    ACK_RECV = 0x0040,
};

enum class OnivVerifyAlg : uint16_t
{
    NONE = 0x0000,
    IV_SIMPLE_XOR = 0x0001,
    IV_AES_128_GCM_SHA256 = 0x1301,
    IV_AES_128_CCM_SHA256 = 0x1304,
};

enum class OnivKeyAgrAlg : uint16_t
{
    NONE = 0x0000,
    KA_SIMPLE_XOR = 0x0001,
    KA_SECP384R1 = 0x0018,
    KA_SECP521R1 = 0x0019,
};

enum class OnivSigAlg : uint16_t
{
    NONE = 0x0000,
    RSA_PKCS1_SHA256 = 0x0401,
    RSA_PKCS1_SHA384 = 0x0501,
    RSA_PKCS1_SHA512 = 0x0601,
    ECDSA_SECP384R1_SHA384 = 0x0503,
    ECDSA_SECP521R1_SHA512 = 0x0603,
};

struct OnivCommon
{
    uint16_t type, flag;
    /*
        密钥协商消息中会传输的证书、签名和公钥会导致无法在一个数据包中发送全部信息，因此需要进行分片
        len表示OnivCommon之后数据的大小
        total表示包含所有信息在内的密钥协商消息大小
        offset表示OnivCommon之后的数据在整个密钥协商消息中的偏移
        total和offset是为了在密钥协商消息的接收方重组密钥协商消息而添加的
    */
    uint16_t identifier, len, total, offset;
    uint8_t UUID[16];

    void linearization(uint8_t *p);
    size_t structuration(const uint8_t *p);

    static uint16_t count();

    static size_t LinearSize();
    static void ConstructEncapHdr(uint8_t *hdr, uint16_t identifier, in_addr_t SrcAddr, in_addr_t DestAddr, in_port_t SrcPort, in_port_t DestPort, size_t OnivSize);
    static uint16_t IPChecksum(const uint8_t *buf, size_t len);
    static uint16_t UDPChecksum(const uint8_t *buf, size_t len);
};

template <typename T> constexpr uint16_t CastTo16(T v)
{
    return static_cast<uint16_t>(v);
}

template <typename T> T CastFrom16(uint16_t u);

template <typename T> struct OnivIDSet
{
    vector<T> IDSet;
    OnivIDSet();
    OnivIDSet(const initializer_list<T> &ids);
    OnivIDSet(const OnivIDSet &IDSet) = delete;
    OnivIDSet& operator=(const OnivIDSet &IDSet) = delete;
    size_t LinearSize();
    void linearization(uint8_t *p);
    size_t structuration(const uint8_t *p);
};

template <typename T> OnivIDSet<T>::OnivIDSet()
{

}

template <typename T> OnivIDSet<T>::OnivIDSet(const initializer_list<T> &ids)
{
    IDSet.assign(ids.begin(), ids.end());
}

template <typename T> size_t OnivIDSet<T>::LinearSize()
{
    return sizeof(uint16_t) + IDSet.size() * sizeof(uint16_t);
}

template <typename T> void OnivIDSet<T>::linearization(uint8_t *p)
{
    *(uint16_t*)p = htons(IDSet.size());
    p += sizeof(uint16_t);
    for(uint16_t i = 0; i < IDSet.size(); i++)
    {
        *(uint16_t*)p = htons(CastTo16<T>(IDSet[i]));
        p += sizeof(uint16_t);
    }
}

template <typename T> size_t OnivIDSet<T>::structuration(const uint8_t *p)
{
    const uint8_t *origin = p;
    uint16_t IDNum = ntohs(*(uint16_t*)p);
    p += sizeof(uint16_t);
    IDSet.clear();
    for(size_t i = 0; i < IDNum; i++)
    {
        IDSet.push_back(CastFrom16<T>(ntohs(*(uint16_t*)p)));
        p += sizeof(uint16_t);
    }
    return p - origin;
}

struct OnivCertChain
{
    vector<string> CertChain;
    OnivCertChain();
    OnivCertChain(const vector<string> &certs);
    OnivCertChain(const OnivCertChain &CertChain) = delete;
    OnivCertChain& operator=(const OnivCertChain &CertChain) = delete;
    // OnivCertChain& operator=(const vector<string> &certs);
    size_t LinearSize();
    void linearization(uint8_t *p);
    size_t structuration(const uint8_t *p);
};

#endif
