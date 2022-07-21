package com.aliyun.gmsse.crypto;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * 国密 SM2 非对称加/解密算法工具类
 * BC 库 SM2 算法签名/验签使用 DER 编码；加密/解密使用 c1||c2||c3 旧标准，不使用 DER 编码
 * <p>
 * 此工具类
 * encrypt/decrypt: 使用 c1||c3||c2 新标准，不使用 DER 编码
 * encryptWithDER/decryptWithDER: 使用 c1||c3||c2 新标准，使用 DER 编码
 * <p>
 * encryptOld/decryptOld: 使用 c1||c2||c3 旧标准，不使用 DER 编码
 * encryptOldWithDER/decryptOldWithDER: 使用 c1||c2||c3 旧标准，使用 DER 编码
 * <p>
 * sign/verify: 签名/验签方法不使用 DER 编码
 * signWithAsn1/verifyWithAsn1: 签名/验签方法使用 DER 编码
 *
 * @author changhr2013
 */
public abstract class SM2 {

    /**
     * 密钥算法类型
     */
    public static final String KEY_ALGORITHM = "EC";

    /**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "SM3withSM2";

    /**
     * KeyMap 中公钥索引 KEY
     */
    private static final String PUBLIC_KEY = "SM2PublicKey";

    /**
     * KeyMap 中私钥索引 KEY
     */
    private static final String PRIVATE_KEY = "SM2PrivateKey";

    /**
     * SM2 标准杂凑值
     */
    private static final byte[] USER_ID = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    private static final int RS_LEN = 32;

    /**
     * SM2 标准曲线名称
     */
    private static final String SM2_CURVE_NAME = "sm2p256v1";

    /**
     * SM2 标准曲线
     */
    private static final X9ECParameters SM2_X9_EC_PARAMETERS = GMNamedCurves.getByName(SM2_CURVE_NAME);

    private static final ECDomainParameters SM2_DOMAIN_PARAMETERS = new ECNamedDomainParameters(GMNamedCurves.getOID(SM2_CURVE_NAME), SM2_X9_EC_PARAMETERS);

    private static final ECParameterSpec SM2_PARAMETER_SPEC = new ECNamedCurveParameterSpec(SM2_CURVE_NAME, SM2_X9_EC_PARAMETERS.getCurve(), SM2_X9_EC_PARAMETERS.getG(), SM2_X9_EC_PARAMETERS.getN());

    /**
     * 使用私钥对数据签名，结果为 ASN1 格式的 rs 的字节数组
     *
     * @param msg            待签名数据
     * @param swapPrivateKey SM2 交换私钥
     * @return ASN1 编码的签名
     */
    public static byte[] signWithAsn1(byte[] msg, byte[] swapPrivateKey) {
        return signWithAsn1(msg, USER_ID, swapPrivateKey);
    }

    /**
     * 使用私钥对数据签名，结果为 ASN1 格式的 rs 的字节数组
     *
     * @param msg            待签名数据
     * @param userId         签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param swapPrivateKey SM2 交换私钥
     * @return ASN1 编码的签名
     */
    public static byte[] signWithAsn1(byte[] msg, byte[] userId, byte[] swapPrivateKey) {
        return signWithAsn1(msg, userId, buildPrivateKey(swapPrivateKey));
    }

    /**
     * 使用私钥对数据签名，结果为 ASN1 格式的 rs 的字节数组
     *
     * @param msg        待签名数据
     * @param userId     签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param privateKey {@link PrivateKey}
     * @return ASN1 编码的签名
     */
    public static byte[] signWithAsn1(byte[] msg, byte[] userId, PrivateKey privateKey) {
        return sign(msg, userId, privateKey, StandardDSAEncoding.INSTANCE);
    }

    /**
     * 使用私钥对数据签名
     *
     * @param msg        待签名数据
     * @param userId     签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param privateKey {@link PrivateKey}
     * @param encoding   签名的编码方式
     * @return 签名
     */
    public static byte[] sign(byte[] msg, byte[] userId, PrivateKey privateKey, DSAEncoding encoding) {
        SM2Signer signer = new SM2Signer(encoding, new SM3Digest());
        try {
            AsymmetricKeyParameter ecParam = ECUtil.generatePrivateKeyParameter(privateKey);
            signer.init(true, new ParametersWithID(ecParam, userId));
            signer.update(msg, 0, msg.length);
            return signer.generateSignature();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 验证 ASN1 格式的签名
     *
     * @param msg           待验签的数据
     * @param swapPublicKey SM2 交换公钥
     * @param asn1Sign      ASN1 编码的签名
     * @return boolean
     */
    public static boolean verifyWithAsn1(byte[] msg, byte[] swapPublicKey, byte[] asn1Sign) {
        return verifyWithAsn1(msg, USER_ID, swapPublicKey, asn1Sign);
    }

    /**
     * 验证 ASN1 格式的签名
     *
     * @param msg           待验签的数据
     * @param userId        签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param swapPublicKey SM2 交换公钥
     * @param asn1Sign      ASN1 编码的签名
     * @return boolean
     */
    public static boolean verifyWithAsn1(byte[] msg, byte[] userId, byte[] swapPublicKey, byte[] asn1Sign) {
        return verifyWithAsn1(msg, userId, buildPublicKey(swapPublicKey), asn1Sign);
    }

    /**
     * 验证 ASN1 格式的签名
     *
     * @param msg       待验签的数据
     * @param userId    签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param publicKey {@link PublicKey}
     * @param asn1Sign  ASN1 编码的签名
     * @return boolean
     */
    public static boolean verifyWithAsn1(byte[] msg, byte[] userId, PublicKey publicKey, byte[] asn1Sign) {
        return verify(msg, userId, publicKey, asn1Sign, StandardDSAEncoding.INSTANCE);
    }

    /**
     * 验证 ASN1 格式的签名
     *
     * @param msg       待验签的数据
     * @param userId    签名者身份信息，默认应使用 "1234567812345678".getBytes()
     * @param publicKey {@link PublicKey}
     * @param signature 未编码的签名
     * @param encoding  签名的编码方式
     * @return boolean
     */
    public static boolean verify(byte[] msg, byte[] userId, PublicKey publicKey, byte[] signature, DSAEncoding encoding) {
        SM2Signer signer = new SM2Signer(encoding, new SM3Digest());
        try {
            AsymmetricKeyParameter ecParam = ECUtil.generatePublicKeyParameter(publicKey);
            signer.init(false, new ParametersWithID(ecParam, userId));
            signer.update(msg, 0, msg.length);
            return signer.verifySignature(signature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * BC 的 SM3withSM2 签名得到的结果的 rs 是 asn1 格式的，这个方法转换成直接拼接的 r||s
     *
     * @param asn1Sign rs in asn1 format
     * @return sign result in plain byte array
     */
    public static byte[] rsAsn1ToPlainByteArray(byte[] asn1Sign) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(asn1Sign);
        byte[] r = bigIntToFixedLengthBytes(ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue());
        byte[] s = bigIntToFixedLengthBytes(ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue());
        byte[] result = new byte[RS_LEN * 2];
        System.arraycopy(r, 0, result, 0, r.length);
        System.arraycopy(s, 0, result, RS_LEN, s.length);
        return result;
    }

    /**
     * BC 的 SM3withSM2 验签需要的 rs 是 asn1 格式的，这个方法将直接拼接 r||s 的字节数组转化成 asn1 格式
     *
     * @param sign in plain byte array
     * @return rs result in asn1 format
     */
    public static byte[] rsPlainByteArrayToAsn1(byte[] sign) {
        if (sign.length != RS_LEN * 2) {
            throw new RuntimeException("error rs.");
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sign, 0, RS_LEN));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sign, RS_LEN, RS_LEN * 2));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 将 BigInteger 转换为定长的字节数组
     *
     * @param rOrS BigInteger
     * @return byte[] 定长的字节数组，长度为 32(RS_LEN)
     */
    private static byte[] bigIntToFixedLengthBytes(BigInteger rOrS) {
        // for sm2p256v1, n is 00fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123,
        // n and s are the result of mod n, so they should be less than n and have length < 32.
        byte[] rs = rOrS.toByteArray();
        if (rs.length == RS_LEN) {
            return rs;
        } else if (rs.length == RS_LEN + 1 && rs[0] == 0) {
            return Arrays.copyOfRange(rs, 1, RS_LEN + 1);
        } else if (rs.length < RS_LEN) {
            byte[] result = new byte[RS_LEN];
            Arrays.fill(result, (byte) 0);
            System.arraycopy(rs, 0, result, RS_LEN - rs.length, rs.length);
            return result;
        } else {
            throw new RuntimeException("error rs: " + Hex.toHexString(rs));
        }
    }

    /**
     * 使用旧标准 c1||c2||c3 顺序的 SM2 非对称公钥加密
     *
     * @param data          待加密数据
     * @param swapPublicKey SM2 交换公钥
     * @return byte[]
     */
    public static byte[] encryptOld(byte[] data, byte[] swapPublicKey) {
        return encrypt(data, buildPublicKey(swapPublicKey), SM2Engine.Mode.C1C2C3);
    }

    /**
     * 使用新标准 c1||c3||c2 顺序的 SM2 非对称公钥加密
     *
     * @param data          待加密数据
     * @param swapPublicKey SM2 交换公钥
     * @return byte[] 加密后的数据
     */
    public static byte[] encrypt(byte[] data, byte[] swapPublicKey) {
        return encrypt(data, buildPublicKey(swapPublicKey), SM2Engine.Mode.C1C3C2);
    }

    /**
     * 使用新标准 c1||c3||c2 顺序的 SM2 非对称公钥加密
     * 加密结果使用 ASN1 编码
     *
     * @param data          待加密数据
     * @param swapPublicKey SM2 交换公钥
     * @return byte[] 加密后的数据
     */
    public static byte[] encryptWithAsn1(byte[] data, byte[] swapPublicKey) {
        return changeC1C2C3ToC1C3C2WithAsn1(encryptOld(data, swapPublicKey));
    }

    /**
     * SM2 非对称公钥加密
     *
     * @param data      待加密数据
     * @param publicKey SM2 公钥，{@link PublicKey}
     * @param mode      加密模式，{@link SM2Engine.Mode}
     * @return byte[]
     */
    public static byte[] encrypt(byte[] data, PublicKey publicKey, SM2Engine.Mode mode) {
        SM2Engine sm2Engine = new SM2Engine(mode);
        try {
            AsymmetricKeyParameter ecParam = ECUtil.generatePublicKeyParameter(publicKey);
            sm2Engine.init(true, new ParametersWithRandom(ecParam, CryptoServicesRegistrar.getSecureRandom()));
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (InvalidCipherTextException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 使用旧标准 c1||c2||c3 顺序的 SM2 非对称私钥解密
     *
     * @param data           密文
     * @param swapPrivateKey SM2 交换私钥
     * @return byte[] 解密后的数据
     */
    public static byte[] decryptOld(byte[] data, byte[] swapPrivateKey) {
        return decrypt(data, buildPrivateKey(swapPrivateKey), SM2Engine.Mode.C1C2C3);
    }

    /**
     * 使用新标准 c1||c3||c2 顺序的 SM2 非对称私钥解密
     *
     * @param data           密文
     * @param swapPrivateKey SM2 交换私钥
     * @return byte[]
     */
    public static byte[] decrypt(byte[] data, byte[] swapPrivateKey) {
        return decrypt(data, buildPrivateKey(swapPrivateKey), SM2Engine.Mode.C1C3C2);
    }

    /**
     * 使用新标准 c1||c3||c2 顺序的 SM2 非对称私钥解密
     * 密文使用 ASN1 编码
     *
     * @param data           密文
     * @param swapPrivateKey SM2 交换私钥
     * @return byte[]
     */
    public static byte[] decryptWithAsn1(byte[] data, byte[] swapPrivateKey) {
        return decryptOld(changeAsn1C1C3C2ToC1C2C3(data), swapPrivateKey);
    }

    /**
     * SM2 非对称私钥解密
     *
     * @param data       密文
     * @param privateKey SM2 私钥，{@link PrivateKey}
     * @param mode       解密模式，{@link SM2Engine.Mode}
     * @return byte[]
     */
    public static byte[] decrypt(byte[] data, PrivateKey privateKey, SM2Engine.Mode mode) {
        byte[] unCompressed = convertDataToUnCompressed(data);
        SM2Engine sm2Engine = new SM2Engine(mode);
        try {
            AsymmetricKeyParameter ecParam = ECUtil.generatePrivateKeyParameter(privateKey);
            sm2Engine.init(false, ecParam);
            return sm2Engine.processBlock(unCompressed, 0, unCompressed.length);
        } catch (InvalidCipherTextException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * BC 库解密时密文中的 c1 要求为非压缩格式
     * 此方法判断密文中的 c1 是否压缩，如果压缩就转换为未压缩的再给 BC 库解密
     *
     * @param data 公钥加密的密文
     * @return 未压缩 c1 的密文
     */
    public static byte[] convertDataToUnCompressed(byte[] data) {
        ECPoint p;
        int expectedLength = (SM2_X9_EC_PARAMETERS.getCurve().getFieldSize() + 7) / 8;
        byte type = data[0];
        byte[] c1;

        switch (type) {
            // infinity
            case 0x00: {
                p = SM2_X9_EC_PARAMETERS.getCurve().getInfinity();
                c1 = new byte[1];
                System.arraycopy(data, 0, c1, 0, c1.length);
                break;
            }
            // compressed
            case 0x02:
            case 0x03: {
                c1 = new byte[expectedLength + 1];
                System.arraycopy(data, 0, c1, 0, c1.length);
                p = SM2_X9_EC_PARAMETERS.getCurve().decodePoint(c1);
                break;
            }
            // uncompressed
            case 0x04: {
                return data;
            }
            // hybrid
            case 0x06:
            case 0x07: {
                c1 = new byte[2 * expectedLength + 1];
                System.arraycopy(data, 0, c1, 0, c1.length);
                p = SM2_X9_EC_PARAMETERS.getCurve().decodePoint(c1);
                break;
            }
            default:
                throw new IllegalArgumentException("Invalid point encoding 0x" + Integer.toString(type, 16));
        }

        byte[] completeC1 = p.getEncoded(false);

        byte[] result = new byte[completeC1.length + data.length - c1.length];
        System.arraycopy(completeC1, 0, result, 0, completeC1.length);
        System.arraycopy(data, c1.length, result, completeC1.length, data.length - c1.length);
        return result;
    }

    /**
     * BC 加解密使用旧标 c1||c2||c3，此方法在加密后调用，将结果转换为 c1||c3||c2
     *
     * @param c1c2c3 c1c2c3 拼接顺序的 byte 数组
     * @return byte[] c1c3c2
     */
    private static byte[] changeC1C2C3ToC1C3C2(byte[] c1c2c3) {
        // sm2p256v1 的这个固定 65。可以看 GMNamedCurves、ECCurve 代码
        final int c1Len = (SM2_X9_EC_PARAMETERS.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        // 长度为 new SM3Digest().getDigestSize()
        final int c3Len = 32;
        byte[] result = new byte[c1c2c3.length];
        // c1
        System.arraycopy(c1c2c3, 0, result, 0, c1Len);
        // c3
        System.arraycopy(c1c2c3, c1c2c3.length - c3Len, result, c1Len, c3Len);
        // c2
        System.arraycopy(c1c2c3, c1Len, result, c1Len + c3Len, c1c2c3.length - c1Len - c3Len);
        return result;
    }

    /**
     * 将 【c1||c2||c3 格式的密文】转换为【DER 编码的 c1||c3||c2 格式的密文】
     *
     * @param c1c2c3 c1||c2||c3 格式的密文
     * @return DER 编码的 c1||c3||c2 格式的密文
     */
    @SuppressWarnings("Duplicates")
    private static byte[] changeC1C2C3ToC1C3C2WithAsn1(byte[] c1c2c3) {
        // sm2p256v1 的这个固定 65。可以看 GMNamedCurves、ECCurve 代码
        final int c1Len = (SM2_X9_EC_PARAMETERS.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        byte[] c1 = new byte[c1Len];
        System.arraycopy(c1c2c3, 0, c1, 0, c1Len);

        BigInteger x = SM2_X9_EC_PARAMETERS.getCurve().decodePoint(c1).getXCoord().toBigInteger();
        BigInteger y = SM2_X9_EC_PARAMETERS.getCurve().decodePoint(c1).getYCoord().toBigInteger();

        // 长度为 new SM3Digest().getDigestSize()
        final int c3Len = 32;
        byte[] c3 = new byte[c3Len];
        System.arraycopy(c1c2c3, c1c2c3.length - c3Len, c3, 0, c3Len);

        final int c2Len = c1c2c3.length - c1Len - c3Len;
        byte[] c2 = new byte[c2Len];
        System.arraycopy(c1c2c3, c1Len, c2, 0, c2Len);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(x));
        v.add(new ASN1Integer(y));
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));
        try {
            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 为 c1||c2||c3 格式的密文添加 DER 编码
     *
     * @param c1c2c3 c1||c2||c3 格式的密文
     * @return DER 编码的 c1||c2||c3 格式的密文
     */
    @SuppressWarnings("Duplicates")
    private static byte[] encodeC1C2C3ToAsn1(byte[] c1c2c3) {
        // sm2p256v1 的这个固定 65。可以看 GMNamedCurves、ECCurve 代码
        final int c1Len = (SM2_X9_EC_PARAMETERS.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        byte[] c1 = new byte[c1Len];
        System.arraycopy(c1c2c3, 0, c1, 0, c1Len);

        BigInteger x = SM2_X9_EC_PARAMETERS.getCurve().decodePoint(c1).getXCoord().toBigInteger();
        BigInteger y = SM2_X9_EC_PARAMETERS.getCurve().decodePoint(c1).getYCoord().toBigInteger();

        // 长度为 new SM3Digest().getDigestSize()
        final int c3Len = 32;
        byte[] c3 = new byte[c3Len];
        System.arraycopy(c1c2c3, c1c2c3.length - c3Len, c3, 0, c3Len);

        final int c2Len = c1c2c3.length - c1Len - c3Len;
        byte[] c2 = new byte[c2Len];
        System.arraycopy(c1c2c3, c1Len, c2, 0, c2Len);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(x));
        v.add(new ASN1Integer(y));
        v.add(new DEROctetString(c2));
        v.add(new DEROctetString(c3));
        try {
            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * BC 加解密使用旧标 c1||c2||c3，此方法在解密前调用，将密文转换为 c1||c2||c3 再去解密
     *
     * @param c1c3c2 c1c3c2 拼接的 byte 数组
     * @return byte[] c1c2c3
     */
    private static byte[] changeC1C3C2ToC1C2C3(byte[] c1c3c2) {
        // sm2p256v1 的这个固定 65。可以看 GMNamedCurves、ECCurve 代码
        final int c1Len = (SM2_X9_EC_PARAMETERS.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        // 长度为 new SM3Digest().getDigestSize()
        final int c3Len = 32;
        byte[] result = new byte[c1c3c2.length];
        // c1
        System.arraycopy(c1c3c2, 0, result, 0, c1Len);
        // c2
        System.arraycopy(c1c3c2, c1Len + c3Len, result, c1Len, c1c3c2.length - c1Len - c3Len);
        // c3
        System.arraycopy(c1c3c2, c1Len, result, c1c3c2.length - c3Len, c3Len);
        return result;
    }

    /**
     * 将【DER 编码的 c1||c3||c2 格式的密文】转换为【c1||c2||c3 格式的密文】
     *
     * @param asn1C1C2C3 DER 编码的 c1||c3||c2 格式的密文
     * @return c1||c2||c3 格式的密文
     */
    @SuppressWarnings("Duplicates")
    private static byte[] changeAsn1C1C3C2ToC1C2C3(byte[] asn1C1C2C3) {
        ASN1Sequence sequence;
        try {
            sequence = (ASN1Sequence) DERSequence.fromByteArray(asn1C1C2C3);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        BigInteger x = ASN1Integer.getInstance(sequence.getObjectAt(0)).getPositiveValue();
        BigInteger y = ASN1Integer.getInstance(sequence.getObjectAt(1)).getPositiveValue();
        byte[] c1 = SM2_X9_EC_PARAMETERS.getCurve().validatePoint(x, y).getEncoded(false);
        byte[] c3 = ((ASN1OctetString) sequence.getObjectAt(2)).getOctets();
        byte[] c2 = ((ASN1OctetString) sequence.getObjectAt(3)).getOctets();
        byte[] c1c2c3 = new byte[c1.length + c2.length + c3.length];
        System.arraycopy(c1, 0, c1c2c3, 0, c1.length);
        System.arraycopy(c2, 0, c1c2c3, c1.length, c2.length);
        System.arraycopy(c3, 0, c1c2c3, c1.length + c2.length, c3.length);
        return c1c2c3;
    }

    /**
     * 将【DER 编码的 c1||c2||c3 格式的密文】转换为【c1||c2||c3 格式的密文】
     *
     * @param asn1C1C2C3 DER 编码的 c1||c2||c3 格式的密文
     * @return c1||c2||c3 格式的密文
     */
    @SuppressWarnings("Duplicates")
    private static byte[] decodeAsn1C1C2C3(byte[] asn1C1C2C3) {
        ASN1Sequence sequence;
        try {
            sequence = (ASN1Sequence) DERSequence.fromByteArray(asn1C1C2C3);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        BigInteger x = ASN1Integer.getInstance(sequence.getObjectAt(0)).getPositiveValue();
        BigInteger y = ASN1Integer.getInstance(sequence.getObjectAt(1)).getPositiveValue();
        byte[] c1 = SM2_X9_EC_PARAMETERS.getCurve().validatePoint(x, y).getEncoded(false);
        byte[] c2 = ((ASN1OctetString) sequence.getObjectAt(2)).getOctets();
        byte[] c3 = ((ASN1OctetString) sequence.getObjectAt(3)).getOctets();
        byte[] c1c2c3 = new byte[c1.length + c2.length + c3.length];
        System.arraycopy(c1, 0, c1c2c3, 0, c1.length);
        System.arraycopy(c2, 0, c1c2c3, c1.length, c2.length);
        System.arraycopy(c3, 0, c1c2c3, c1.length + c2.length, c3.length);
        return c1c2c3;
    }

    /**
     * 生成 SM2 密钥对
     *
     * @return Map 密钥 Map
     */
    public static Map<String, Key> initKey() {
        // 生成密钥对
        KeyPair keyPair = initKeyPair();
        // 封装密钥
        Map<String, Key> keyMap = new HashMap<>(2);
        keyMap.put(PUBLIC_KEY, keyPair.getPublic());
        keyMap.put(PRIVATE_KEY, keyPair.getPrivate());
        return keyMap;
    }

    /**
     * 生成 SM2 密钥对
     *
     * @return 密钥对，{@link KeyPair}
     */
    public static KeyPair initKeyPair() {
        try {
            KeyPairGeneratorSpi.EC ecKeyPairGen = new KeyPairGeneratorSpi.EC(KEY_ALGORITHM, BouncyCastleProvider.CONFIGURATION);
            ecKeyPairGen.initialize(SM2_PARAMETER_SPEC, CryptoServicesRegistrar.getSecureRandom());
            // 生成密钥对
            return ecKeyPairGen.generateKeyPair();
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException("invalid algorithm parameter exception.", e);
        }
    }

    /**
     * 获取私钥分量 D 作为交换的私钥
     *
     * @param keyMap 密钥 Map
     * @return byte[] SM2 交换私钥（私钥分量 D 的字节数组）
     */
    public static byte[] getSwapPrivateKey(Map<String, Key> keyMap) {
        BCECPrivateKey privateKey = (BCECPrivateKey) keyMap.get(PRIVATE_KEY);
        return bigIntToFixedLengthBytes(privateKey.getD());
    }

    /**
     * 获取公钥分量 X，Y 作为交换的公钥（65 个字节）
     * 默认不压缩公钥
     *
     * @param keyMap 密钥 Map
     * @return SM2 交换公钥（公钥分量 X，Y 拼合的字节数组）
     */
    public static byte[] getSwapPublicKey(Map<String, Key> keyMap) {
        BCECPublicKey publicKey = (BCECPublicKey) keyMap.get(PUBLIC_KEY);
        return publicKey.getQ().getEncoded(false);
    }

    /**
     * 获取公钥分量 X，Y 作为交换的公钥（65 个字节或 33 个字节）
     *
     * @param keyMap     密钥 Map
     * @param compressed 公钥是否进行压缩
     * @return byte[] SM2 交换公钥（公钥分量 X，Y 拼合的字节数组）
     */
    public static byte[] getSwapPublicKey(Map<String, Key> keyMap, boolean compressed) {
        BCECPublicKey publicKey = (BCECPublicKey) keyMap.get(PUBLIC_KEY);
        return publicKey.getQ().getEncoded(compressed);
    }

    /**
     * 从证书获取公钥
     *
     * @param file X509 文件
     * @return 公钥
     */
    public static PublicKey getPublicKeyFromX509File(File file) {
        try {
            try (FileInputStream in = new FileInputStream(file)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
                X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(in);
                return certificate.getPublicKey();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 从交换私钥还原完整的 BCECPrivateKey
     *
     * @param swapPrivateKey 交换私钥（D 分量字节数组）
     * @return {@link BCECPrivateKey} 完整的私钥
     */
    public static PrivateKey buildPrivateKey(byte[] swapPrivateKey) {
        BigInteger d = new BigInteger(1, swapPrivateKey);
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, SM2_PARAMETER_SPEC);
        return new BCECPrivateKey(KEY_ALGORITHM, ecPrivateKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * 从交换公钥的字节数组中还原出 BCECPublicKey
     *
     * @param swapPublicKey 交换公钥的字节数组（标志位 + 点）
     * @return {@link BCECPublicKey} 完整的公钥
     */
    public static PublicKey buildPublicKey(byte[] swapPublicKey) {
        ECPoint ecPoint = SM2_X9_EC_PARAMETERS.getCurve().decodePoint(swapPublicKey);
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, SM2_PARAMETER_SPEC);
        return new BCECPublicKey(KEY_ALGORITHM, ecPublicKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * 从完整的 BCECPrivateKey 获取交换私钥
     *
     * @param privateKey {@link BCECPrivateKey} 完整的私钥
     * @return 交换私钥（D 分量字节数组）
     */
    public static byte[] extractSwapPrivateKey(PrivateKey privateKey) {
        return BigIntegers.asUnsignedByteArray(32, ((BCECPrivateKey) privateKey).getD());
    }

    /**
     * 从完整的 BCECPublicKey 获取交换公钥
     *
     * @param publicKey {@link BCECPublicKey} 完整的公钥
     * @return 交换公钥的字节数组（标志位 + 点）
     */
    public static byte[] extractSwapPublicKey(PublicKey publicKey) {
        return ((BCECPublicKey) publicKey).getQ().getEncoded(false);
    }

    /**
     * 从完整的 BCECPublicKey 获取交换公钥
     *
     * @param publicKey  {@link BCECPublicKey} 完整的公钥
     * @param compressed 是否进行压缩
     * @return 交换公钥的字节数组（标志位 + 点）
     */
    public static byte[] extractSwapPublicKey(PublicKey publicKey, boolean compressed) {
        return ((BCECPublicKey) publicKey).getQ().getEncoded(compressed);
    }

    /**
     * 通过私钥生成预处理数据
     *
     * @param inData         原始输入数据
     * @param swapPrivateKey 交换私钥（D 分量字节数组）
     * @return 预处理后的输入数据
     */
    public static byte[] getPreDataByPrivateKey(byte[] inData, byte[] swapPrivateKey) {
        try {
            AsymmetricKeyParameter ecParam = ECUtil.generatePrivateKeyParameter(buildPrivateKey(swapPrivateKey));
            byte[] z = getZ(true, new ParametersWithID(ecParam, USER_ID));
            return hashMergeInData(z, inData);
        } catch (Exception e) {
            throw new RuntimeException("ECUtil generate private key failed", e);
        }
    }

    /**
     * 通过公钥生成预处理数据
     *
     * @param inData        交换公钥的字节数组（标志位 + 点）
     * @param swapPublicKey 公钥原始值
     * @return 预处理后的输入数据
     */
    public static byte[] getPreDataByPublicKey(byte[] inData, byte[] swapPublicKey) {
        try {
            AsymmetricKeyParameter ecParam = ECUtil.generatePublicKeyParameter(buildPublicKey(swapPublicKey));
            byte[] z = getZ(false, new ParametersWithID(ecParam, USER_ID));
            return hashMergeInData(z, inData);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("ECUtil generate public key failed", e);
        }
    }

    private static byte[] hashMergeInData(byte[] z, byte[] inData) {
        SM3Digest digest = new SM3Digest();
        digest.update(z, 0, z.length);
        digest.update(inData, 0, inData.length);

        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        digest.reset();
        return result;
    }

    /**
     * SM2 预处理
     *
     * @param forSigning 是否是签名操作
     * @param param      公钥 or 私钥
     * @return 预处理的前缀参数
     */
    private static byte[] getZ(boolean forSigning, CipherParameters param) {

        final DSAKCalculator kCalculator = new RandomDSAKCalculator();

        final SM3Digest digest = new SM3Digest();

        ECPoint pubPoint;
        ECKeyParameters ecKey;
        ECDomainParameters ecParams;

        CipherParameters baseParam;
        byte[] userID;

        if (param instanceof ParametersWithID) {
            baseParam = ((ParametersWithID) param).getParameters();
            userID = ((ParametersWithID) param).getID();
        } else {
            baseParam = param;
            userID = Hex.decode("31323334353637383132333435363738"); // the default value
        }

        if (forSigning) {
            if (baseParam instanceof ParametersWithRandom) {
                ParametersWithRandom rParam = (ParametersWithRandom) baseParam;

                ecKey = (ECKeyParameters) rParam.getParameters();
                ecParams = ecKey.getParameters();
                kCalculator.init(ecParams.getN(), rParam.getRandom());
            } else {
                ecKey = (ECKeyParameters) baseParam;
                ecParams = ecKey.getParameters();
                kCalculator.init(ecParams.getN(), CryptoServicesRegistrar.getSecureRandom());
            }
            pubPoint = new FixedPointCombMultiplier().multiply(ecParams.getG(), ((ECPrivateKeyParameters) ecKey).getD()).normalize();
        } else {
            ecKey = (ECKeyParameters) baseParam;
            ecParams = ecKey.getParameters();
            pubPoint = ((ECPublicKeyParameters) ecKey).getQ();
        }

        digest.reset();

        addUserID(digest, userID);

        addFieldElement(digest, ecParams.getCurve().getA());
        addFieldElement(digest, ecParams.getCurve().getB());
        addFieldElement(digest, ecParams.getG().getAffineXCoord());
        addFieldElement(digest, ecParams.getG().getAffineYCoord());
        addFieldElement(digest, pubPoint.getAffineXCoord());
        addFieldElement(digest, pubPoint.getAffineYCoord());

        byte[] result = new byte[digest.getDigestSize()];

        digest.doFinal(result, 0);

        return result;
    }

    private static void addUserID(Digest digest, byte[] userID) {
        int len = userID.length * 8;
        digest.update((byte) (len >> 8 & 0xFF));
        digest.update((byte) (len & 0xFF));
        digest.update(userID, 0, userID.length);
    }

    private static void addFieldElement(Digest digest, ECFieldElement v) {
        byte[] p = v.getEncoded();
        digest.update(p, 0, p.length);
    }

}