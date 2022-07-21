package com.aliyun.gmsse.handshake;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;
import org.bouncycastle.tls.TlsUtils;

public class CertificateRequest extends Handshake.Body {

    private byte[] certificateType;

    private byte[] pad;

    public CertificateRequest(byte[] certificateType, byte[] pad) {
        this.certificateType = certificateType;
        this.pad = pad;
    }

    @Override
    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        TlsUtils.writeOpaque8(certificateType, os);
        os.write(pad);
        return os.toByteArray();
    }

    public static Body read(InputStream input) {
        try {
            byte[] types = TlsUtils.readOpaque8(input);

            byte[] pad = new byte[input.available()];
            input.read(pad);
            return new CertificateRequest(types, pad);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
