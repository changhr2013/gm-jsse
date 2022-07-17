package com.aliyun.gmsse;

import java.security.cert.X509Certificate;

/**
 * 表示本端在连接中的角色，为客户端或服务端
 */
enum ConnectionEnd {
    // 本端在连接中的角色
    server,
    client
}

/**
 * 用于数据加解密的密码算法
 */
enum BulkCipherAlgorithm {
    // 加解密算法
    sm1,
    sm4
}

/**
 * 表示密码算法的类型
 */
enum CipherType {
    // 算法类型
    block
}

/**
 * 用于计算和校验消息完整性的密码杂凑算法
 */
enum MACAlgorithm {
    // hash 算法
    sha_1,
    sm3
}

/**
 * a. {@link ConnectionEnd}
 * b. {@link BulkCipherAlgorithm}
 * c. {@link CipherType}
 * d. {@link MACAlgorithm}
 * e. hash_size
 * f. {@link CompressionMethod}
 * g. master_secret: 在协商过程中由预主密钥、客户端随机数、服务端随机数计算出的 48 字节密钥
 * h. client_random: 由客户端产生的 32 字节随机数据
 * i. server_random: 由服务端产生的 32 字节随机数据
 * j. record_iv_length: IV 长度
 * k. mac_length: MAC 长度
 */
public class SecurityParameters {
    ConnectionEnd entity;
    // BulkCipherAlgorithm bulk_cipher_algorithm;
    // CipherType cipher_type;
    byte recordIVLength;
    public byte[] clientRandom;
    public byte[] serverRandom;
    public X509Certificate encryptionCert;
    public byte[] masterSecret;
}