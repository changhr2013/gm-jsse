package com.aliyun.gmsse.utils;

import cn.hutool.core.io.FileUtil;
import org.bouncycastle.jcajce.provider.keystore.pkcs12.PKCS12KeyStoreSpi;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class Pkcs12Util {

    private Pkcs12Util() {
    }

    public static List<String> listAlias(String path, String password) {
        List<String> aliasList = new ArrayList<>();

        PKCS12KeyStoreSpi.BCPKCS12KeyStore pkcs12KeyStore = new PKCS12KeyStoreSpi.BCPKCS12KeyStore();

        File pkcs12File = FileUtil.file(path);
        try (FileInputStream inputStream = new FileInputStream(pkcs12File)) {
            pkcs12KeyStore.engineLoad(inputStream, password.toCharArray());

            Enumeration<String> aliasEnum = pkcs12KeyStore.engineAliases();

            while (aliasEnum.hasMoreElements()) {
                aliasList.add(aliasEnum.nextElement());
            }

            return aliasList;
        } catch (Exception e) {
            throw new RuntimeException("read key from pkcs#12 file exception", e);
        }
    }

    public static Key readKey(String path, String keyAlias, String password) {
        PKCS12KeyStoreSpi.BCPKCS12KeyStore pkcs12KeyStore = new PKCS12KeyStoreSpi.BCPKCS12KeyStore();
        File pkcs12File = FileUtil.file(path);
        try (FileInputStream inputStream = new FileInputStream(pkcs12File)) {
            pkcs12KeyStore.engineLoad(inputStream, password.toCharArray());
            return pkcs12KeyStore.engineGetKey(keyAlias, password.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException("read key from pkcs#12 file exception", e);
        }
    }

    public static void writeKey(String path, String keyAlias, Key key, Certificate[] chain, String password) {
        PKCS12KeyStoreSpi.BCPKCS12KeyStore pkcs12KeyStore = new PKCS12KeyStoreSpi.BCPKCS12KeyStore();

        // 判断写入的文件是否存在
        boolean exist = FileUtil.exist(path);
        File pkcs12File = exist ? FileUtil.file(path) : FileUtil.touch(path);

        try {
            // 如果 pkcs#12 文件存在，就先加载文件
            if (exist) {
                try (FileInputStream inputStream = new FileInputStream(pkcs12File)) {
                    pkcs12KeyStore.engineLoad(inputStream, password.toCharArray());
                }
            }
            // 写入私钥对应的证书链
            pkcs12KeyStore.engineSetKeyEntry(keyAlias, key, password.toCharArray(), chain);
        } catch (Exception e) {
            throw new RuntimeException("read or operate pkcs#12 keystore exception", e);
        }

        try (FileOutputStream outputStream = new FileOutputStream(pkcs12File)) {
            pkcs12KeyStore.engineStore(outputStream, password.toCharArray());
            outputStream.flush();
        } catch (Exception e) {
            throw new RuntimeException("write pkcs#12 file exception", e);
        }
    }

    public static Certificate[] readCertificateChain(String path, String certAlias, String password) {
        PKCS12KeyStoreSpi.BCPKCS12KeyStore pkcs12KeyStore = new PKCS12KeyStoreSpi.BCPKCS12KeyStore();
        File pkcs12File = FileUtil.file(path);
        try (FileInputStream inputStream = new FileInputStream(pkcs12File)) {
            pkcs12KeyStore.engineLoad(inputStream, password.toCharArray());
            return pkcs12KeyStore.engineGetCertificateChain(certAlias);
        } catch (Exception e) {
            throw new RuntimeException("read key from pkcs#12 file exception", e);
        }
    }

    public static void writeCertificate(String path, String certAlias, Certificate cert, String password) {
        PKCS12KeyStoreSpi.BCPKCS12KeyStore pkcs12KeyStore = new PKCS12KeyStoreSpi.BCPKCS12KeyStore();

        // 判断写入的文件是否存在
        boolean exist = FileUtil.exist(path);
        File pkcs12File = exist ? FileUtil.file(path) : FileUtil.touch(path);

        try {
            // 如果 pkcs#12 文件存在，就先加载文件
            if (exist) {
                try (FileInputStream inputStream = new FileInputStream(pkcs12File)) {
                    pkcs12KeyStore.engineLoad(inputStream, password.toCharArray());
                }
            }
            // 写入证书
            pkcs12KeyStore.engineSetCertificateEntry(certAlias, cert);
        } catch (Exception e) {
            throw new RuntimeException("read or operate pkcs#12 keystore exception", e);
        }

        try (FileOutputStream outputStream = new FileOutputStream(pkcs12File)) {
            pkcs12KeyStore.engineStore(outputStream, password.toCharArray());
            outputStream.flush();
        } catch (Exception e) {
            throw new RuntimeException("write pkcs#12 file exception", e);
        }
    }


}
