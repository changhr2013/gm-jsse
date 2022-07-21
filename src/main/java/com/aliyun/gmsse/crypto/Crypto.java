package com.aliyun.gmsse.crypto;

import java.security.*;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

public class Crypto {

    /**
     * SM2 非对称加密
     *
     * @param publicKey       公钥
     * @param preMasterSecret 预主密钥
     * @return 密文
     */
    public static byte[] encryptWithAsn1(PublicKey publicKey, byte[] preMasterSecret) {
        return SM2.encryptWithAsn1(preMasterSecret, SM2.extractSwapPublicKey(publicKey));
    }

    /**
     * 数据扩展函数 P_hash
     *
     * @param secret 进行计算所需要的密钥
     * @param seed   进行计算所需要的数据
     * @param output 计算出的要求长度的数据
     */
    private static void hmacHash(byte[] secret, byte[] seed, byte[] output) throws IllegalStateException {
        KeyParameter keyParameter = new KeyParameter(secret);
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);

        byte[] a = seed;

        int macSize = mac.getMacSize();

        byte[] b1 = new byte[macSize];
        byte[] b2 = new byte[macSize];

        int pos = 0;
        while (pos < output.length) {
            mac.update(a, 0, a.length);
            mac.doFinal(b1, 0);
            a = b1;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(b2, 0);
            System.arraycopy(b2, 0, output, pos, Math.min(macSize, output.length - pos));
            pos += macSize;
        }
    }

    /**
     * 伪随机函数 PRF，计算方法如下：
     * PRF(secret, label, seed) = P_SM3(secret, label + seed)
     */
    public static byte[] prf(byte[] secret, byte[] label, byte[] seed, int length) throws IllegalStateException {
        byte[] labelSeed = join(label, seed);
        byte[] result = new byte[length];
        hmacHash(secret, labelSeed, result);
        return result;
    }

    /**
     * SM3 函数
     *
     * @param bytes 原文
     * @return SM3 结果
     */
    public static byte[] hash(byte[] bytes) {
        Digest digest = new SM3Digest();
        byte[] output = new byte[digest.getDigestSize()];
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(output, 0);
        return output;
    }

    /**
     * SM2 签名，签名结果使用 ASN1 编码
     *
     * @param msg        待签名的消息
     * @param privateKey 私钥
     * @return ASN1 格式的签名
     */
    public static byte[] signWithAsn1(byte[] msg, PrivateKey privateKey) {
        try {
            AsymmetricKeyParameter ecParam = ECUtil.generatePrivateKeyParameter(privateKey);
            SM2Signer signer = new SM2Signer(StandardDSAEncoding.INSTANCE, new SM3Digest());
            signer.init(true, ecParam);
            signer.update(msg, 0, msg.length);
            return signer.generateSignature();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 将两个字节数组拼接
     *
     * @param a 第一个字节数组
     * @param b 第二个字节数组
     * @return 合并后的字节数组
     */
    private static byte[] join(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

}
