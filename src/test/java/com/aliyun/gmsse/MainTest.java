package com.aliyun.gmsse;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jsse.util.CustomSSLSocketFactory;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.junit.Assert;
import org.junit.Test;
import sun.security.ssl.SSLContextImpl;

public class MainTest {
    @Test
    public void test() throws IOException, NoSuchAlgorithmException, KeyManagementException, Exception {

//        Path path = new File("C:\\Users\\chang\\GitHub\\gm-jsse\\src\\test\\resources\\AAA.cer").toPath();
        Path path = new File("C:\\Users\\chang\\GitHub\\gm-jsse\\src\\test\\resources\\gmsslcn-root.cer").toPath();

        Certificate certificate = CertificateFactory.getInstance("X.509", new BouncyCastleProvider()).generateCertificate(Files.newInputStream(path));
        GMX509TrustManager gmx509TrustManager = new GMX509TrustManager(new X509Certificate[]{(X509Certificate) certificate});


        SSLContext sslContext = SSLContext.getInstance("TLSv1.2", new BouncyCastleJsseProvider());
        sslContext.init(null, new TrustManager[]{gmx509TrustManager}, new SecureRandom());

        GMSSLSocketFactory mySSLSocketFactory = new GMSSLSocketFactory(null, gmx509TrustManager, new SecureRandom(), sslContext.getClientSessionContext());
        CustomSSLSocketFactory socketFactory = new CustomSSLSocketFactory(mySSLSocketFactory);


//        GMProvider provider = new GMProvider();
//        SSLContext sc = SSLContext.getInstance("TLS", provider);
//        sc.init(null, new TrustManager[]{gmx509TrustManager}, null);
//        SSLSocketFactory ssf = sc.getSocketFactory();

//        URL serverUrl = new URL("https://sm2test.ovssl.cn/");
//        URL serverUrl = new URL("https://demo.gmssl.cn");
        URL serverUrl = new URL("https://demo.gmssl.cn:2443");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        // set SSLSocketFactory
        conn.setSSLSocketFactory(socketFactory);
        conn.connect();
        Assert.assertEquals(200, conn.getResponseCode());
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", conn.getCipherSuite());
    }
}
