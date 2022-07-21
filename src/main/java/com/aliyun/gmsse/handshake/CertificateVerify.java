package com.aliyun.gmsse.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.List;

import com.aliyun.gmsse.crypto.Crypto;
import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;
import org.bouncycastle.tls.TlsUtils;

public class CertificateVerify extends Handshake.Body {

    private byte[] signature;

    public CertificateVerify(byte[] signature) {
        this.signature = signature;
    }

    public CertificateVerify(PrivateKey clientPrivateKey, List<Handshake> handshakes) throws IOException {

        ByteArrayOutputStream os = new ByteArrayOutputStream();

        for (Handshake handshake : handshakes) {
            os.write(handshake.getBytes());
        }

        byte[] hash = Crypto.hash(os.toByteArray());

        this.signature = Crypto.signWithAsn1(hash, clientPrivateKey);
    }

    @Override
    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        TlsUtils.writeOpaque16(this.signature, os);
        return os.toByteArray();
    }

    public byte[] getSignature() {
        return signature;
    }

    public static Body read(InputStream input) {
        try {
            byte[] sign = TlsUtils.readOpaque16(input);
            return new CertificateVerify(sign);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
