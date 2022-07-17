package com.aliyun.gmsse.crypto;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.ShortBufferException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

public class Crypto {
    private static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
    private static ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

    public static byte[] encrypt(BCECPublicKey key, byte[] preMasterSecret)
            throws IOException, InvalidCipherTextException {
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(key.getQ(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
        byte[] c1c3c2 = sm2Engine.processBlock(preMasterSecret, 0, preMasterSecret.length);

        // sm2p256v1的这个固定65。可看GMNamedCurves、ECCurve代码。
        final int c1Len = (x9ECParameters.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        // new SM3Digest().getDigestSize();
        final int c3Len = 32;
        // 第一个字节为固定的 0x04
        // c1x
        byte[] c1x = new byte[32];
        System.arraycopy(c1c3c2, 1, c1x, 0, 32);
        // c1y
        byte[] c1y = new byte[32];
        System.arraycopy(c1c3c2, c1x.length + 1, c1y, 0, 32);

        // 32 字节的签名
        // c3
        byte[] c3 = new byte[c3Len];
        System.arraycopy(c1c3c2, c1Len, c3, 0, c3Len);

        // 被加密的字节，长度与加密前的字节一致
        int c2len = c1c3c2.length - c1Len - c3Len;
        // c2
        byte[] c2 = new byte[c2len];
        System.arraycopy(c1c3c2, c1Len + c3Len, c2, 0, c2len);

        // 重新编码为 ASN1 格式
        return encode(c1x, c1y, c3, c2);
    }

    public static byte[] encode(byte[] c1x, byte[] c1y, byte[] c3, byte[] c2) throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(c1x));
        v.add(new ASN1Integer(c1y));
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));
        DERSequence seq = new DERSequence(v);
        return seq.getEncoded();
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

    /**
     * 数据扩展函数 P_hash
     *
     * @param secret 进行计算所需要的密钥
     * @param seed   进行计算所需要的数据
     * @param output 计算出的要求长度的数据
     */
    private static void hmacHash(byte[] secret, byte[] seed, byte[] output)
            throws InvalidKeyException, NoSuchAlgorithmException, ShortBufferException, IllegalStateException {
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
    public static byte[] prf(byte[] secret, byte[] label, byte[] seed, int length)
            throws InvalidKeyException, NoSuchAlgorithmException, ShortBufferException, IllegalStateException {
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
}
