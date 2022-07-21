package com.aliyun.gmsse;

import cn.hutool.core.io.FileUtil;
import com.aliyun.gmsse.Record.ContentType;
import com.aliyun.gmsse.crypto.Crypto;
import com.aliyun.gmsse.handshake.*;
import com.aliyun.gmsse.record.Alert;
import com.aliyun.gmsse.record.AppDataInputStream;
import com.aliyun.gmsse.record.AppDataOutputStream;
import com.aliyun.gmsse.record.ChangeCipherSpec;
import com.aliyun.gmsse.record.Handshake;

import com.aliyun.gmsse.utils.CertificateUtil;
import com.aliyun.gmsse.utils.PemUtil;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * GMSSLSocket
 */
public class GMSSLSocket extends SSLSocket {
    static List<CipherSuite> supportedSuites = new ArrayList<CipherSuite>();
    static List<ProtocolVersion> supportedProtocols = new ArrayList<ProtocolVersion>();

    static {
        // setup suites
        supportedSuites.add(CipherSuite.NTLS_SM2_WITH_SM4_SM3);

        // setup protocols
        supportedProtocols.add(ProtocolVersion.NTLS_1_1);
    }

    GMSSLSession session;
    BufferedOutputStream handshakeOut;
    int port;
    private boolean createSessions;
    public SSLSessionContext sessionContext;
    private String remoteHost;
    private boolean clientMode;
    private Socket underlyingSocket;
    private int underlyingPort;
    private boolean autoClose;
    // raw socket in/out
    private InputStream socketIn;
    private OutputStream socketOut;
    private RecordStream recordStream;

    private SecurityParameters securityParameters = new SecurityParameters();
    List<Handshake> handshakes = new ArrayList<Handshake>();

    public GMSSLSocket(String host, int port) throws IOException {
        super(host, port);
        remoteHost = host;
        initialize();
    }

    private void initialize() {
        session = new GMSSLSession(supportedSuites, supportedProtocols);
        session.protocol = ProtocolVersion.NTLS_1_1;
    }

    public GMSSLSocket(InetAddress host, int port) throws IOException {
        super(host, port);
        remoteHost = host.getHostName();
        if (remoteHost == null) {
            remoteHost = host.getHostAddress();
        }
        initialize();
    }

    public GMSSLSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        underlyingSocket = socket;
        remoteHost = host;
        underlyingPort = port;
        this.autoClose = autoClose;
        initialize();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public boolean getEnableSessionCreation() {
        return createSessions;
    }

    @Override
    public String[] getEnabledCipherSuites() {
        List<String> suites = new ArrayList<String>();
        for (CipherSuite suite : session.enabledSuites) {
            suites.add(suite.getName());
        }
        return suites.toArray(new String[0]);
    }

    @Override
    public String[] getEnabledProtocols() {
        List<String> protocols = new ArrayList<String>();
        for (ProtocolVersion version : session.enabledProtocols) {
            protocols.add(version.toString());
        }
        return protocols.toArray(new String[0]);
    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public SSLSession getSession() {
        return session;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        List<String> suites = new ArrayList<String>();
        for (CipherSuite suite : supportedSuites) {
            suites.add(suite.getName());
        }
        return suites.toArray(new String[0]);
    }

    @Override
    public String[] getSupportedProtocols() {
        List<String> protocols = new ArrayList<String>();
        for (ProtocolVersion version : supportedProtocols) {
            protocols.add(version.toString());
        }
        return protocols.toArray(new String[0]);
    }

    @Override
    public boolean getUseClientMode() {
        return clientMode;
    }

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        createSessions = flag;
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        if (suites == null || suites.length == 0) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < suites.length; i++) {
            if (CipherSuite.forName(suites[i]) == null) {
                throw new IllegalArgumentException("unsupported suite: " + suites[i]);
            }
        }

        synchronized (session.enabledSuites) {
            session.enabledSuites.clear();
            for (int i = 0; i < suites.length; i++) {
                CipherSuite suite = CipherSuite.forName(suites[i]);
                if (!session.enabledSuites.contains(suite)) {
                    session.enabledSuites.add(suite);
                }
            }
        }
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        if (protocols == null || protocols.length == 0) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < protocols.length; i++) {
            if (!(protocols[i].equalsIgnoreCase("NTLSv1.1"))) {
                throw new IllegalArgumentException("unsupported protocol: " + protocols[i]);
            }
        }

        synchronized (session.enabledProtocols) {
            session.enabledProtocols.clear();
            for (int i = 0; i < protocols.length; i++) {
                session.enabledProtocols.add(ProtocolVersion.NTLS_1_1);
            }
        }
    }

    @Override
    public void setNeedClientAuth(boolean need) {
    }

    @Override
    public void setUseClientMode(boolean mode) {
        clientMode = mode;
    }

    @Override
    public void setWantClientAuth(boolean want) {
    }

    @Override
    public void startHandshake() throws IOException {
        ensureConnect();

        // send ClientHello
        sendClientHello();

        // receive ServerHello
        receiveServerHello();

        // receive ServerCertificate
        receiveServerCertificate();

        // receive ServerKeyExchange
        receiveServerKeyExchange();

        // receive Server CertificateRequest
        receiveServerCertificateRequest();

        // receive ServerHelloDone
        receiveServerHelloDone();

        // send Client Certificate
        sendClientCertificate();

        // send ClientKeyExchange
        sendClientKeyExchange();

        // send Client CertificateVerify
        sendClientCertificateVerify();

        // send ChangeCipherSpec
        sendChangeCipherSpec();

        // send Finished
        sendFinished();

        // receive ChangeCipherSpec
        receiveChangeCipherSpec();

        // receive finished
        receiveFinished();
    }

    private void sendClientHello() throws IOException {
        byte[] sessionId = new byte[0];
        int gmtUnixTime = (int) (System.currentTimeMillis() / 1000L);
        ClientRandom random = new ClientRandom(gmtUnixTime, session.random.generateSeed(28));
        List<CipherSuite> suites = session.enabledSuites;
        List<CompressionMethod> compressions = new ArrayList<CompressionMethod>(2);
        compressions.add(CompressionMethod.NULL);
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        ClientHello ch = new ClientHello(version, random, sessionId, suites, compressions);
        Handshake hs = new Handshake(Handshake.Type.CLIENT_HELLO, ch);
        Record rc = new Record(Record.ContentType.HANDSHAKE, version, hs.getBytes());
        recordStream.write(rc);
        handshakes.add(hs);
        securityParameters.clientRandom = random.getBytes();
    }

    private void receiveServerHello() throws IOException {
        Record rc = recordStream.read();
        if (rc.contentType != Record.ContentType.HANDSHAKE) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.UNEXPECTED_MESSAGE);
            throw new AlertException(alert, true);
        }

        Handshake hsf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        ServerHello sh = (ServerHello) hsf.body;
        sh.getCompressionMethod();
        // TODO: process the compresion method
        session.cipherSuite = sh.getCipherSuite();
        session.peerHost = remoteHost;
        session.peerPort = port;
        session.sessionId = new GMSSLSession.ID(sh.getSessionId());
        handshakes.add(hsf);
        securityParameters.serverRandom = sh.getRandom();
    }

    private void receiveServerCertificate() throws IOException {
        Record rc = recordStream.read();
        Handshake cf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        Certificate cert = (Certificate) cf.body;
        X509Certificate[] peerCerts = cert.getCertificates();
        try {
            session.trustManager.checkServerTrusted(peerCerts, session.cipherSuite.getAuthType());
        } catch (CertificateException e) {
            throw new SSLException("could not verify peer certificate!", e);
        }
        session.peerCerts = peerCerts;
        session.peerVerified = true;
        handshakes.add(cf);
    }

    private void receiveServerKeyExchange() throws IOException {
        Record rc = recordStream.read();
        Handshake skef = Handshake.read(new ByteArrayInputStream(rc.fragment));
        ServerKeyExchange ske = (ServerKeyExchange) skef.body;
        // signature cert
        X509Certificate signCert = session.peerCerts[0];
        // encryption cert
        X509Certificate encryptionCert = session.peerCerts[1];
        // verify the signature
        boolean verified = false;

        try {
            verified = ske.verify(signCert.getPublicKey(), securityParameters.clientRandom,
                    securityParameters.serverRandom, encryptionCert);
        } catch (Exception e2) {
            throw new SSLException("server key exchange verify fails!", e2);
        }

        if (!verified) {
            throw new SSLException("server key exchange verify fails!");
        }

        handshakes.add(skef);
        securityParameters.encryptionCert = encryptionCert;
    }

    private void receiveServerCertificateRequest() throws IOException {
        Record rc = recordStream.read();
        Handshake shdf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        handshakes.add(shdf);
    }

    private void receiveServerHelloDone() throws IOException {
        Record rc = recordStream.read();
        Handshake shdf = Handshake.read(new ByteArrayInputStream(rc.fragment));
        handshakes.add(shdf);
    }

    private void sendClientCertificate() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;

        java.security.cert.Certificate sigCert = CertificateUtil.readCertificate(Files.newInputStream(Paths.get("src/test/resources/client_sig.cer")));
        java.security.cert.Certificate encCert = CertificateUtil.readCertificate(Files.newInputStream(Paths.get("src/test/resources/client_enc.cer")));
        java.security.cert.Certificate middleCert = CertificateUtil.readCertificate(Files.newInputStream(Paths.get("src/test/resources/middleCert.cer")));
        X509Certificate[] chain = new X509Certificate[3];
        chain[0] = (X509Certificate) sigCert;
        chain[1] = (X509Certificate) encCert;
        chain[2] = (X509Certificate) middleCert;

        Certificate ckex = new Certificate(chain);
        Handshake hs = new Handshake(Handshake.Type.CERTIFICATE, ckex);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        recordStream.write(rc);
        handshakes.add(hs);
    }

    private void sendClientKeyExchange() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        ClientKeyExchange ckex = new ClientKeyExchange(version, session.random, securityParameters.encryptionCert);
        Handshake hs = new Handshake(Handshake.Type.CLIENT_KEY_EXCHANGE, ckex);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        recordStream.write(rc);
        handshakes.add(hs);
        try {
            securityParameters.masterSecret = ckex.getMasterSecret(securityParameters.clientRandom,
                    securityParameters.serverRandom);
        } catch (Exception e) {
            e.printStackTrace();
            throw new SSLException("caculate master secret failed", e);
        }

        // key_block = PRF(SecurityParameters.master_secret，"keyexpansion"，
        // SecurityParameters.server_random +SecurityParameters.client_random);
        // new TLSKeyMaterialSpec(masterSecret, TLSKeyMaterialSpec.KEY_EXPANSION,
        // key_block.length, server_random, client_random))
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(securityParameters.serverRandom);
        os.write(securityParameters.clientRandom);
        byte[] seed = os.toByteArray();
        byte[] keyBlock = null;
        try {
            keyBlock = Crypto.prf(securityParameters.masterSecret, "key expansion".getBytes(), seed, 128);
        } catch (Exception e) {
            throw new SSLException("caculate key block failed", e);
        }

        // client_write_MAC_secret[SecurityParameters.hash_size]
        // server_write_MAC_secret[SecurityParameters.hash_size]
        // client_write_key[SecurityParameters.key_material_length]
        // server_write_key[SecurityParameters.key_material_length]
        // clientWriteIV
        // serverWriteIV

        // client mac key
        byte[] clientMacKey = new byte[32];
        System.arraycopy(keyBlock, 0, clientMacKey, 0, 32);
        recordStream.setClientMacKey(clientMacKey);

        // server mac key
        byte[] serverMacKey = new byte[32];
        System.arraycopy(keyBlock, 32, serverMacKey, 0, 32);
        recordStream.setServerMacKey(serverMacKey);

        // client write key
        byte[] clientWriteKey = new byte[16];
        System.arraycopy(keyBlock, 64, clientWriteKey, 0, 16);
        SM4Engine writeCipher = new SM4Engine();
        writeCipher.init(true, new KeyParameter(clientWriteKey));
        recordStream.setWriteCipher(writeCipher);

        // server write key
        byte[] serverWriteKey = new byte[16];
        System.arraycopy(keyBlock, 80, serverWriteKey, 0, 16);
        SM4Engine readCipher = new SM4Engine();
        readCipher.init(false, new KeyParameter(serverWriteKey));
        recordStream.setReadCipher(readCipher);

        // client write iv
        byte[] clientWriteIV = new byte[16];
        System.arraycopy(keyBlock, 96, clientWriteIV, 0, 16);
        recordStream.setClientWriteIV(clientWriteIV);
        recordStream.setWriteEngine(clientWriteKey, clientWriteIV);

        // server write iv
        byte[] serverWriteIV = new byte[16];
        System.arraycopy(keyBlock, 112, serverWriteIV, 0, 16);
        recordStream.setServerWriteIV(serverWriteIV);
        recordStream.setReadEngine(serverWriteKey, serverWriteIV);
    }

    private void sendClientCertificateVerify() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;

        PrivateKey privateKey = PemUtil.readPemPrivateKey(Files.newInputStream(Paths.get("src/test/resources/client-sig-key.pem")));

        CertificateVerify ckex = new CertificateVerify(privateKey, handshakes);
        Handshake hs = new Handshake(Handshake.Type.CERTIFICATE_VERIFY, ckex);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        recordStream.write(rc);
        handshakes.add(hs);
    }

    private void sendChangeCipherSpec() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        Record rc = new Record(ContentType.CHANGE_CIPHER_SPEC, version, new ChangeCipherSpec().getBytes());
        recordStream.write(rc);
    }

    private void sendFinished() throws IOException {
        ProtocolVersion version = ProtocolVersion.NTLS_1_1;
        Finished finished = new Finished(securityParameters.masterSecret, "client finished", handshakes);
        Handshake hs = new Handshake(Handshake.Type.FINISHED, finished);
        Record rc = new Record(ContentType.HANDSHAKE, version, hs.getBytes());
        recordStream.write(rc, true);
        handshakes.add(hs);
    }

    private void receiveChangeCipherSpec() throws IOException {
        Record rc = recordStream.read();
        ChangeCipherSpec ccs = ChangeCipherSpec.read(new ByteArrayInputStream(rc.fragment));
    }

    private void receiveFinished() throws IOException {
        Record rc = recordStream.read(true);
        Handshake hs = Handshake.read(new ByteArrayInputStream(rc.fragment));
        Finished finished = (Finished) hs.body;
        Finished serverFinished = new Finished(securityParameters.masterSecret, "server finished", handshakes);
        if (!Arrays.equals(finished.getBytes(), serverFinished.getBytes())) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.HANDSHAKE_FAILURE);
            throw new AlertException(alert, true);
        }
    }

    private void ensureConnect() throws IOException {
        if (underlyingSocket != null) {
            if (!underlyingSocket.isConnected()) {
                underlyingSocket.connect(this.getRemoteSocketAddress());
            }
        } else {
            if (!this.isConnected()) {
                SocketAddress socketAddress = new InetSocketAddress(remoteHost, port);
                connect(socketAddress);
            }
        }
        if (underlyingSocket != null) {
            socketIn = underlyingSocket.getInputStream();
            socketOut = underlyingSocket.getOutputStream();
        } else {
            socketIn = super.getInputStream();
            socketOut = super.getOutputStream();
        }
        recordStream = new RecordStream(socketIn, socketOut);
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return new AppDataOutputStream(recordStream);
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return new AppDataInputStream(recordStream);
    }
}
