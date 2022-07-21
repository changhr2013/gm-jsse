package com.aliyun.gmsse.utils;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.*;

import java.io.*;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

/**
 * PEM 操作工具类
 *
 * @author changhr2013
 */
public class PemUtil {

    /**
     * 读取 PEM 格式的私钥
     *
     * @param pemBytes PEM 私钥的字节数组
     * @return 私钥对象 {@link PrivateKey}
     */
    public static PrivateKey readPemPrivateKey(byte[] pemBytes) {
        return readPemPrivateKey(new ByteArrayInputStream(pemBytes));
    }

    /**
     * 读取 PEM 格式的私钥
     *
     * @param pemStream PEM 流
     * @return 私钥对象 {@link PrivateKey}
     */
    public static PrivateKey readPemPrivateKey(InputStream pemStream) {
        return readPemPrivateKey(pemStream, null);
    }

    /**
     * 读取 PEM 格式的私钥
     *
     * @param pemStream PEM 流
     * @param password  密码
     * @return 私钥对象 {@link PrivateKey}
     */
    public static PrivateKey readPemPrivateKey(InputStream pemStream, final char[] password) {

        final Provider provider = new BouncyCastleProvider();

        try (PEMParser pemParser = new PEMParser(new InputStreamReader(pemStream))) {

            Object keyObject = pemParser.readObject();

            JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter().setProvider(provider);

            if (keyObject instanceof PrivateKeyInfo) {
                // PrivateKeyInfo
                return pemKeyConverter.getPrivateKey((PrivateKeyInfo) keyObject);
            } else if (keyObject instanceof PEMKeyPair) {
                // PemKeyPair
                return pemKeyConverter.getKeyPair((PEMKeyPair) keyObject).getPrivate();
            } else if (keyObject instanceof PKCS8EncryptedPrivateKeyInfo) {
                // Encrypted PrivateKeyInfo
                InputDecryptorProvider decryptProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(provider).build(password);
                PrivateKeyInfo privateKeyInfo = ((PKCS8EncryptedPrivateKeyInfo) keyObject).decryptPrivateKeyInfo(decryptProvider);
                return pemKeyConverter.getPrivateKey(privateKeyInfo);
            } else if (keyObject instanceof PEMEncryptedKeyPair) {
                // Encrypted PemKeyPair
                PEMDecryptorProvider decryptProvider = new JcePEMDecryptorProviderBuilder().setProvider(provider).build(password);
                PrivateKeyInfo privateKeyInfo = ((PEMEncryptedKeyPair) keyObject).decryptKeyPair(decryptProvider).getPrivateKeyInfo();
                return pemKeyConverter.getPrivateKey(privateKeyInfo);
            } else {
                throw new RuntimeException("unsupported private key pem string");
            }

        } catch (IOException | OperatorCreationException | PKCSException e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * 读取 PEM 格式的公钥
     *
     * @param pemBytes PEM 公钥的字节数组
     * @return 公钥对象 {@link PublicKey}
     */
    public static PublicKey readPemPublicKey(byte[] pemBytes) {
        return readPemPublicKey(new ByteArrayInputStream(pemBytes));
    }

    /**
     * 读取 PEM 格式的公钥
     *
     * @param pemStream PEM 输入流
     * @return 公钥对象 {@link PublicKey}
     */
    public static PublicKey readPemPublicKey(InputStream pemStream) {
        final Provider provider = new BouncyCastleProvider();

        try (PEMParser pemParser = new PEMParser(new InputStreamReader(pemStream))) {

            Object keyObject = pemParser.readObject();

            JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter().setProvider(provider);

            if (keyObject instanceof SubjectPublicKeyInfo) {
                // SubjectPublicKeyInfo
                return pemKeyConverter.getPublicKey((SubjectPublicKeyInfo) keyObject);
            } else if (keyObject instanceof X509CertificateHolder) {
                // X509 Certificate
                return pemKeyConverter.getPublicKey(((X509CertificateHolder) keyObject).getSubjectPublicKeyInfo());
            } else if (keyObject instanceof PEMKeyPair) {
                // PemKeyPair
                return pemKeyConverter.getKeyPair((PEMKeyPair) keyObject).getPublic();
            } else if (keyObject instanceof X509TrustedCertificateBlock) {
                // X509 Trusted Certificate
                return pemKeyConverter.getPublicKey(((X509TrustedCertificateBlock) keyObject).getCertificateHolder().getSubjectPublicKeyInfo());
            } else if (keyObject instanceof PKCS10CertificationRequest) {
                // PKCS#10 CSR
                return pemKeyConverter.getPublicKey(((PKCS10CertificationRequest) keyObject).getSubjectPublicKeyInfo());
            } else {
                throw new RuntimeException("unsupported public key pem string");
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 从 PEM 流中读取 PEM 的内容
     *
     * @param inputStream PEM 输入流
     * @return PEM 的内容字节数组
     */
    public static byte[] readPemContent(InputStream inputStream) {
        PemObject pemObject = readPemObject(inputStream);
        if (null != pemObject) {
            return pemObject.getContent();
        }
        return null;
    }

    /**
     * 读取 PEM 文件中的信息，包括类型、头信息和密钥内容
     *
     * @param inputStream PEM 输入流
     * @return {@link PemObject}
     */
    public static PemObject readPemObject(InputStream inputStream) {
        return readPemObject(new InputStreamReader(inputStream));
    }

    /**
     * 读取 PEM 文件中的信息，包括类型、头信息和密钥内容
     *
     * @param reader PemReader
     * @return {@link PemObject}
     */
    public static PemObject readPemObject(Reader reader) {
        try (PemReader pemReader = new PemReader(reader)) {
            return pemReader.readPemObject();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 将私钥转换为 PEM 格式字符串输出
     *
     * @param privateKey 私钥对象
     * @param encryptor  私钥加密方式
     * @return 私钥 PEM 字符串
     */
    public static String generatePemPrivateKey(PrivateKey privateKey, OutputEncryptor encryptor) {
        try {
            return generatePemString(new JcaPKCS8Generator(privateKey, encryptor));
        } catch (PemGenerationException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 将公钥转换为 PEM 格式字符串输出
     *
     * @param publicKey 公钥对象
     * @return 公钥 PEM 字符串
     */
    public static String generatePemPublicKey(PublicKey publicKey) {
        try {
            return generatePemString(new JcaMiscPEMGenerator(publicKey));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 将 PEM 对象转换为 PEM 格式的字符串
     *
     * @param pemObject 实现 PemObjectGenerator 接口的 PEM 对象
     * @return PEM 字符串
     */
    public static String generatePemString(PemObjectGenerator pemObject) {
        final StringWriter stringWriter = new StringWriter();
        writePemObject(pemObject, stringWriter);
        return stringWriter.toString();
    }

    /**
     * 写出 PEM 对象到 OutputStream（私钥、公钥、证书等）
     *
     * @param pemObject    实现 PemObjectGenerator 接口的 PEM 对象
     * @param outputStream PEM 输出流
     */
    public static void writePemObject(PemObjectGenerator pemObject, OutputStream outputStream) {
        writePemObject(pemObject, new OutputStreamWriter(outputStream));
    }

    /**
     * 写出 PEM 字符串到 Writer（私钥、公钥、证书等）
     *
     * @param pemObject 实现 PemObjectGenerator 接口的 PEM 对象
     * @param writer    PemWriter
     */
    public static void writePemObject(PemObjectGenerator pemObject, Writer writer) {
        try (PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(pemObject);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
