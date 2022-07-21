package com.aliyun.gmsse;

import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.*;

import cn.hutool.core.io.FileUtil;
import com.aliyun.gmsse.utils.Pkcs12Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jsse.util.CustomSSLSocketFactory;
import org.junit.Assert;
import org.junit.Test;

public class MainTest {

    @Test
    public void testGm() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        File file = new File("C:\\Users\\chang\\GitHub\\gm-jsse\\src\\test\\resources\\AAA.cer");
//        Path path = new File("C:\\Users\\chang\\GitHub\\gm-jsse\\src\\test\\resources\\gmsslcn-root.cer").toPath();


        BouncyCastleProvider bc = new BouncyCastleProvider();
        KeyStore ks = KeyStore.getInstance("JKS");
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        FileInputStream is = new FileInputStream(file);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        ks.load(null, null);
        ks.setCertificateEntry("gmca", cert);

        GMProvider provider = new GMProvider();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
        tmf.init(ks);


        SSLContext sc = SSLContext.getInstance("TLS", provider);
        sc.init(null, tmf.getTrustManagers(), null);
        SSLSocketFactory ssf = sc.getSocketFactory();

        URL serverUrl = new URL("https://sm2test.ovssl.cn/");

//        URL serverUrl = new URL("https://demo.gmssl.cn");
//        URL serverUrl = new URL("https://demo.gmssl.cn:1443");
//        URL serverUrl = new URL("https://demo.gmssl.cn:2443");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        // set SSLSocketFactory
        conn.setSSLSocketFactory(ssf);
        conn.connect();
        Assert.assertEquals(200, conn.getResponseCode());
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", conn.getCipherSuite());
    }

    @Test
    public void test() throws IOException, NoSuchAlgorithmException, KeyManagementException, Exception {

        Security.addProvider(new BouncyCastleProvider());

        byte[] keyBytes = FileUtil.readBytes(new File("C:\\Users\\chang\\GitHub\\gm-jsse\\src\\test\\resources\\client.key"));

        Certificate clientCert = CertificateFactory.getInstance("X.509", new BouncyCastleProvider()).generateCertificate(FileUtil.getInputStream(new File("C:\\Users\\chang\\GitHub\\gm-jsse\\src\\test\\resources\\client.cer")));
        Certificate clientRootCert = CertificateFactory.getInstance("X.509", new BouncyCastleProvider()).generateCertificate(FileUtil.getInputStream(new File("C:\\Users\\chang\\GitHub\\gm-jsse\\src\\test\\resources\\client-root.cer")));

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(FileUtil.getInputStream(new File("C:\\Users\\chang\\GitHub\\gm-jsse\\src\\test\\resources\\newclientsig.p12")), "12345678".toCharArray());

        System.out.println(ks.aliases().nextElement());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, "12345678".toCharArray());
        KeyManager[] keyManagers = kmf.getKeyManagers();

//        Path path = new File("C:\\Users\\chang\\GitHub\\gm-jsse\\src\\test\\resources\\AAA.cer").toPath();
        Path path = new File("C:\\Users\\chang\\GitHub\\gm-jsse\\src\\test\\resources\\gmsslcn-root.cer").toPath();

        Certificate certificate = CertificateFactory.getInstance("X.509", new BouncyCastleProvider()).generateCertificate(Files.newInputStream(path));
        GMX509TrustManager gmx509TrustManager = new GMX509TrustManager(new X509Certificate[]{(X509Certificate) certificate});


        SSLContext sslContext = SSLContext.getInstance("TLSv1.2", new BouncyCastleJsseProvider());
        sslContext.init(keyManagers, new TrustManager[]{gmx509TrustManager}, new SecureRandom());

        GMSSLSocketFactory mySSLSocketFactory = new GMSSLSocketFactory((X509KeyManager) keyManagers[0], gmx509TrustManager, new SecureRandom(), sslContext.getClientSessionContext());
        CustomSSLSocketFactory socketFactory = new CustomSSLSocketFactory(mySSLSocketFactory);


//        GMProvider provider = new GMProvider();
//        SSLContext sc = SSLContext.getInstance("TLS", provider);
//        sc.init(null, new TrustManager[]{gmx509TrustManager}, null);
//        SSLSocketFactory ssf = sc.getSocketFactory();

//        URL serverUrl = new URL("https://sm2test.ovssl.cn/");

//        URL serverUrl = new URL("https://demo.gmssl.cn");
        URL serverUrl = new URL("https://demo.gmssl.cn:1443");
//        URL serverUrl = new URL("https://demo.gmssl.cn:2443");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        // set SSLSocketFactory
        conn.setSSLSocketFactory(socketFactory);
        conn.connect();
        Assert.assertEquals(200, conn.getResponseCode());
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", conn.getCipherSuite());
    }

}
