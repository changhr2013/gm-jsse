package com.aliyun.gmsse.crypto;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;

import javax.crypto.spec.SecretKeySpec;

/**
 * 国密 SM4 对称加密算法工具类
 *
 * @author changhr2013
 * @create 2019-05-08 10:21
 */
public abstract class SM4 {

    /**
     * 密钥算法
     */
    public static final String KEY_ALGORITHM = "SM4";

    /**
     * 密钥的字节长度
     */
    public static final int KEY_LENGTH = 16;

    /**
     * 密钥位长度
     */
    public static final int KEY_SIZE = 128;

    /**
     * 加解密算法/工作模式/填充方式
     */
    public static final String ECB_NO_PADDING = "SM4/ECB/NoPadding";
    public static final String ECB_PKCS_7_PADDING = "SM4/ECB/PKCS7Padding";

    public static final String CBC_NO_PADDING = "SM4/CBC/NoPadding";
    public static final String CBC_PKCS_7_PADDING = "SM4/CBC/PKCS7Padding";

    public static final String CTR_NO_PADDING = "SM4/CTR/NoPadding";
    public static final String GCM_NO_PADDING = "SM4/GCM/NoPadding";

    /**
     * 生成 SM4 对称密钥
     *
     * @return SM4 对称密钥，长度为 128 位
     */
    public static byte[] initKey() {
        CipherKeyGenerator keyGenerator = new CipherKeyGenerator();
        keyGenerator.init(new KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), KEY_SIZE));
        byte[] keyBytes = keyGenerator.generateKey();
        SecretKeySpec sm4SecretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        return sm4SecretKey.getEncoded();
    }

    /**
     * 加密
     *
     * @param plainBytes      待加密数据
     * @param keyBytes        密钥
     * @param ivBytes         向量
     * @param cipherAlgorithm 算法/工作模式/填充模式
     * @return byte[] 加密后的密文
     */
    public static byte[] encrypt(byte[] plainBytes, byte[] keyBytes, byte[] ivBytes, final String cipherAlgorithm) {
        if (ECB_NO_PADDING.equalsIgnoreCase(cipherAlgorithm) || ECB_PKCS_7_PADDING.equalsIgnoreCase(cipherAlgorithm)) {
            return BCCipher.encryptByECB(plainBytes, keyBytes, cipherAlgorithm);
        }

        if (GCM_NO_PADDING.equalsIgnoreCase(cipherAlgorithm)) {
            return BCCipher.encryptByGCM(plainBytes, keyBytes, ivBytes, null, cipherAlgorithm);
        }

        return BCCipher.encrypt(plainBytes, keyBytes, ivBytes, cipherAlgorithm);
    }

    /**
     * 解密
     *
     * @param cipherBytes     待解密数据
     * @param keyBytes        密钥
     * @param ivBytes         向量
     * @param cipherAlgorithm 算法/工作模式/填充模式
     * @return byte[] 解密的数据
     */
    public static byte[] decrypt(byte[] cipherBytes, byte[] keyBytes, byte[] ivBytes, final String cipherAlgorithm) {
        if (ECB_NO_PADDING.equalsIgnoreCase(cipherAlgorithm) || ECB_PKCS_7_PADDING.equalsIgnoreCase(cipherAlgorithm)) {
            return BCCipher.decryptByECB(cipherBytes, keyBytes, cipherAlgorithm);
        }

        if (GCM_NO_PADDING.equalsIgnoreCase(cipherAlgorithm)) {
            return BCCipher.decryptByGCM(cipherBytes, keyBytes, ivBytes, null, cipherAlgorithm);
        }

        return BCCipher.decrypt(cipherBytes, keyBytes, ivBytes, cipherAlgorithm);
    }

}
