package com.aliyun.gmsse.utils;

import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;

public class CertificateUtil {

    private CertificateUtil() {
    }

    public static Certificate readCertificate(File file) {
        try (FileInputStream inputStream = new FileInputStream(file)) {
            return new CertificateFactory().engineGenerateCertificate(inputStream);
        } catch (Exception e) {
            throw new RuntimeException("read certificate exception.", e);
        }
    }

    public static Certificate readCertificate(InputStream inputStream) {
        try {
            return new CertificateFactory().engineGenerateCertificate(inputStream);
        } catch (Exception e) {
            throw new RuntimeException("read certificate exception.", e);
        }
    }

}
