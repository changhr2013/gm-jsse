package com.aliyun.gmsse.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * 获取对应算法的 BC BlockCipher，支持 AES 和 SM4
 *
 * @author changhr2013
 */
public class BCCipher {

    /**
     * 获取 BlockCipher
     *
     * @param cipherAlgorithm 算法
     * @return {@link BufferedBlockCipher}
     */
    public static BufferedBlockCipher getInstance(String cipherAlgorithm) {

        String[] transform = cipherAlgorithm.split("/");
        if (transform.length < 3) {
            throw new RuntimeException("unsupported CipherAlgorithm");
        }

        BlockCipher blockCipher;
        if ("AES".equalsIgnoreCase(transform[0])) {
            blockCipher = new AESEngine();
        } else if ("SM4".equalsIgnoreCase(transform[0])) {
            blockCipher = new SM4Engine();
        } else {
            throw new RuntimeException("unsupported cipher algorithm: " + transform[0]);
        }

        if ("CBC".equalsIgnoreCase(transform[1])) {
            blockCipher = new CBCBlockCipher(blockCipher);
        } else if ("CFB".equalsIgnoreCase(transform[1])) {
            blockCipher = new CFBBlockCipher(blockCipher, blockCipher.getBlockSize());
        } else if ("OFB".equalsIgnoreCase(transform[1])) {
            blockCipher = new OFBBlockCipher(blockCipher, blockCipher.getBlockSize());
        } else if ("CTR".equalsIgnoreCase(transform[1])) {
            blockCipher = new SICBlockCipher(blockCipher);
        } else if ("ECB".equalsIgnoreCase(transform[1])) {
            // 默认为 ECB 模式，不需要做处理
        } else {
            throw new RuntimeException("unsupported cipher mode" + transform[1]);
        }

        if ("NoPadding".equalsIgnoreCase(transform[2])) {
            return new BufferedBlockCipher(blockCipher);
        } else if ("PKCS7Padding".equalsIgnoreCase(transform[2])) {
            return new PaddedBufferedBlockCipher(blockCipher);
        } else {
            throw new RuntimeException("unsupported cipher padding" + transform[2]);
        }
    }

    /**
     * 获取 AEAD 算法的 Cipher 对象，支持 GCM 模式
     *
     * @param cipherAlgorithm 算法
     * @return {@link AEADBlockCipher}
     */
    public static AEADBlockCipher getAEADInstance(String cipherAlgorithm) {

        // 解析 JCE 算法格式的字符串
        String[] transform = cipherAlgorithm.split("/");
        if (transform.length < 3) {
            throw new RuntimeException("unsupported CipherAlgorithm");
        }

        // 获取 BlockCipher
        BlockCipher blockCipher;
        if ("AES".equalsIgnoreCase(transform[0])) {
            blockCipher = new AESEngine();
        } else if ("SM4".equalsIgnoreCase(transform[0])) {
            blockCipher = new SM4Engine();
        } else {
            throw new RuntimeException("unsupported cipher algorithm: " + transform[0]);
        }

        // 包装为 GCMBlockCipher
        return new GCMBlockCipher(blockCipher);
    }

    /**
     * 加密
     *
     * @param plainBytes      待加密数据
     * @param keyBytes        密钥
     * @param cipherAlgorithm 算法/工作模式/填充模式
     * @return byte[] 加密后的密文
     */
    protected static byte[] encrypt(byte[] plainBytes, byte[] keyBytes, byte[] ivBytes, final String cipherAlgorithm) {
        try {
            // 初始化 Cipher
            BufferedBlockCipher cipher = BCCipher.getInstance(cipherAlgorithm);
            ParametersWithIV parametersWithIv = new ParametersWithIV(new KeyParameter(keyBytes), ivBytes);
            cipher.init(true, parametersWithIv);

            // 加密
            int updateOutputSize = cipher.getOutputSize(plainBytes.length);
            byte[] out = new byte[updateOutputSize];
            int len = cipher.processBytes(plainBytes, 0, plainBytes.length, out, 0);
            cipher.doFinal(out, len);

            return out;
        } catch (Exception e) {
            throw new RuntimeException(cipherAlgorithm + " encrypt error", e);
        }
    }

    /**
     * 解密
     *
     * @param cipherBytes     待解密数据
     * @param keyBytes        密钥
     * @param cipherAlgorithm 算法/工作模式/填充模式
     * @return byte[] 解密的数据
     */
    protected static byte[] decrypt(byte[] cipherBytes, byte[] keyBytes, byte[] ivBytes, final String cipherAlgorithm) {
        try {
            // 初始化 Cipher
            BufferedBlockCipher cipher = BCCipher.getInstance(cipherAlgorithm);
            ParametersWithIV parametersWithIv = new ParametersWithIV(new KeyParameter(keyBytes), ivBytes);
            cipher.init(false, parametersWithIv);

            // 解密
            int updateOutputSize = cipher.getOutputSize(cipherBytes.length);
            byte[] buf = new byte[updateOutputSize];
            int len = cipher.processBytes(cipherBytes, 0, cipherBytes.length, buf, 0);
            len += cipher.doFinal(buf, len);

            // 移除 Padding
            byte[] out = new byte[len];
            System.arraycopy(buf, 0, out, 0, len);
            return out;
        } catch (Exception e) {
            throw new RuntimeException(cipherAlgorithm + " decrypt error", e);
        }
    }

    /**
     * 加密，ECB 模式
     *
     * @param plainBytes      待加密数据
     * @param keyBytes        密钥
     * @param cipherAlgorithm 算法/工作模式/填充模式
     * @return byte[] 加密后的密文
     */
    protected static byte[] encryptByECB(byte[] plainBytes, byte[] keyBytes, final String cipherAlgorithm) {
        try {
            BufferedBlockCipher cipher = BCCipher.getInstance(cipherAlgorithm);
            cipher.init(true, new KeyParameter(keyBytes));

            // 加密
            int updateOutputSize = cipher.getOutputSize(plainBytes.length);
            byte[] out = new byte[updateOutputSize];
            int len = cipher.processBytes(plainBytes, 0, plainBytes.length, out, 0);
            cipher.doFinal(out, len);

            return out;

        } catch (Exception e) {
            throw new RuntimeException(cipherAlgorithm + " encrypt error", e);
        }
    }

    /**
     * 解密，ECB 模式
     *
     * @param cipherBytes     待解密数据
     * @param keyBytes        密钥
     * @param cipherAlgorithm 算法/工作模式/填充模式
     * @return byte[] 解密的数据
     */
    protected static byte[] decryptByECB(byte[] cipherBytes, byte[] keyBytes, final String cipherAlgorithm) {
        try {
            // 初始化 Cipher
            BufferedBlockCipher cipher = BCCipher.getInstance(cipherAlgorithm);
            cipher.init(false, new KeyParameter(keyBytes));

            // 解密
            // 创建一个临时的 buffer 去存放解密的数据（解密数据带 Padding）
            int updateOutputSize = cipher.getOutputSize(cipherBytes.length);
            byte[] buf = new byte[updateOutputSize];
            int len = cipher.processBytes(cipherBytes, 0, cipherBytes.length, buf, 0);
            len += cipher.doFinal(buf, len);

            // 移除 Padding
            byte[] out = new byte[len];
            System.arraycopy(buf, 0, out, 0, len);
            return out;
        } catch (Exception e) {
            throw new RuntimeException(cipherAlgorithm + " decrypt error", e);
        }
    }

    /**
     * 加密，GCM 模式
     *
     * @param plainBytes      待加密数据
     * @param keyBytes        密钥
     * @param nonceBytes      用来初始化 GCMParameterSpec 的随机数
     * @param aadBytes        Associated data 关联数据
     * @param cipherAlgorithm 算法/工作模式/填充模式
     * @return byte[] 加密后的密文
     */
    protected static byte[] encryptByGCM(byte[] plainBytes, byte[] keyBytes, byte[] nonceBytes, byte[] aadBytes, final String cipherAlgorithm) {
        try {
            AEADBlockCipher cipher = BCCipher.getAEADInstance(cipherAlgorithm);
            AEADParameters aeadParameters = new AEADParameters(new KeyParameter(keyBytes), 128, nonceBytes, aadBytes);
            cipher.init(true, aeadParameters);

            // 解密
            int updateOutputSize = cipher.getOutputSize(plainBytes.length);
            byte[] out = new byte[updateOutputSize];
            int len = cipher.processBytes(plainBytes, 0, plainBytes.length, out, 0);
            cipher.doFinal(out, len);
            return out;

        } catch (Exception e) {
            throw new RuntimeException("AES-GCM decrypt error", e);
        }
    }

    /**
     * 解密，GCM 模式
     *
     * @param cipherBytes     待解密数据
     * @param keyBytes        密钥
     * @param nonceBytes      用来初始化 GCMParameterSpec 的随机数
     * @param aadBytes        Associated data 关联数据
     * @param cipherAlgorithm 算法/工作模式/填充模式
     * @return byte[] 解密后的数据
     */
    protected static byte[] decryptByGCM(byte[] cipherBytes, byte[] keyBytes, byte[] nonceBytes, byte[] aadBytes, final String cipherAlgorithm) {
        try {
            AEADBlockCipher cipher = BCCipher.getAEADInstance(cipherAlgorithm);
            AEADParameters aeadParameters = new AEADParameters(new KeyParameter(keyBytes), 128, nonceBytes, aadBytes);
            cipher.init(false, aeadParameters);

            // 解密
            int outputSize = cipher.getOutputSize(cipherBytes.length);
            byte[] out = new byte[outputSize];
            int len = cipher.processBytes(cipherBytes, 0, cipherBytes.length, out, 0);
            cipher.doFinal(out, len);
            return out;

        } catch (Exception e) {
            throw new RuntimeException("AES-GCM decrypt error", e);
        }
    }
}
