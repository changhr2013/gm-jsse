package com.aliyun.gmsse;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import javax.net.ssl.SSLException;

import com.aliyun.gmsse.Record.ContentType;
import com.aliyun.gmsse.crypto.BCCipher;
import com.aliyun.gmsse.paddings.GmSSLPadding;
import com.aliyun.gmsse.record.Alert;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class RecordStream {
    // 加解密的字节块大小
    public static final int BLOCK_SIZE = 16;

    private OutputStream output;
    private InputStream input;

    private byte[] clientMacKey;
    private byte[] serverMacKey;
    private SM4Engine writeCipher;
    private SM4Engine readCipher;
    private byte[] clientWriteIV;
    private byte[] serverWriteIV;

    private PaddedBufferedBlockCipher writeEngine;

    private PaddedBufferedBlockCipher readEngine;

    public PaddedBufferedBlockCipher getWriteEngine() {
        return writeEngine;
    }

    public void setWriteEngine(byte[] keyBytes, byte[] ivBytes) {
        this.writeEngine = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SM4Engine()), new GmSSLPadding());
        writeEngine.init(true, new ParametersWithIV(new KeyParameter(keyBytes), ivBytes));
    }

    public PaddedBufferedBlockCipher getReadEngine() {
        return readEngine;
    }

    public void setReadEngine(byte[] keyBytes, byte[] ivBytes) {
        this.readEngine = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SM4Engine()));
        this.readEngine.init(false, new ParametersWithIV(new KeyParameter(keyBytes), ivBytes));
    }

    private SequenceNumber readSeqNo = new SequenceNumber(), writeSeqNo = new SequenceNumber();

    public RecordStream(InputStream socketIn, OutputStream socketOut) {
        input = socketIn;
        output = socketOut;
    }

    public void setClientMacKey(byte[] key) {
        this.clientMacKey = key;
    }

    public void setServerMacKey(byte[] key) {
        this.serverMacKey = key;
    }

    public void setWriteCipher(SM4Engine writeCipher) {
        this.writeCipher = writeCipher;
    }

    public void setReadCipher(SM4Engine readCipher) {
        this.readCipher = readCipher;
    }

    public void setClientWriteIV(byte[] clientWriteIV) {
        this.clientWriteIV = clientWriteIV;
    }

    public void setServerWriteIV(byte[] serverWriteIV) {
        this.serverWriteIV = serverWriteIV;
    }

    public void write(Record record) throws IOException {
        BufferedOutputStream os = new BufferedOutputStream(output);
        // content type
        os.write(record.contentType.getValue());
        // version
        os.write(record.version.getMajor());
        os.write(record.version.getMinor());
        // fragment length
        byte[] bytes = record.fragment;
        int length = bytes.length;
        os.write(length >>> 8 & 0xFF);
        os.write(length & 0xFF);
        // fragment bytes
        os.write(bytes);
        os.flush();
    }

    public void write(Record record, boolean needEncrypt) throws IOException {
        write(encrypt(record));
    }

    public Record read() throws IOException {
        return read(false);
    }

    public Record read(boolean encrypted) throws IOException {
        // type(1), version(2), length(2), fragment(length)
        int type = input.read();
        ContentType contentType = ContentType.getInstance(type);
        ProtocolVersion version = ProtocolVersion.getInstance(input.read(), input.read());
        // fragment length
        int length = (input.read() & 0xFF) << 8 | input.read() & 0xFF;

        byte[] fragment = Util.safeRead(input, length);
        // System.out.println("struct {");
        // System.out.println("  type = " + contentType.toString() + ";");
        // System.out.println("  version = " + version.toString() + ";");
        // System.out.println("  length = " + length + ";");
        // System.out.print(Util.hexString(fragment).trim());
        // System.out.println("} TLSCiphertext;");

        if (encrypted) {
            Record record = new Record(contentType, version, fragment);
            byte[] content = decrypt(record);
            return new Record(contentType, version, content);
        }

        if (type == 0x15) {
            Alert alert = Alert.read(new ByteArrayInputStream(fragment));
            throw new SSLException(alert.getDescription().toString());
        }

        return new Record(contentType, version, fragment);
    }

    /**
     * 解密 Record
     * <pre>
     * struct {
     *     opaque IV[SecurityParameters.record_iv_length];
     *     block-ciphered struct {
     *         opaque content[TLSCompressed.length];
     *         opaque MAC[SecurityParameters.mac_length];
     *         uint8 padding_length;
     *         uint8 padding[GenericBlockCipher.padding_length];
     *     };
     * } GenericBlockCipher;
     * </pre>
     *
     * @param record 加密的 Record
     * @return 原文数据
     */
    public byte[] decrypt(Record record) throws IOException {

        byte[] decrypted = decryptByCbc(readEngine, record.fragment);
//        byte[] decrypted = decrypt(record.fragment, readCipher, serverWriteIV);

        int ivLen = 16;
        int macLen = 32;
        int paddingLength = 1;

        byte[] content = new byte[decrypted.length - paddingLength - ivLen - macLen];
        System.arraycopy(decrypted, 16, content, 0, content.length);

        byte[] serverMac = new byte[32];
        System.arraycopy(decrypted, 16 + content.length, serverMac, 0, serverMac.length);

        // HMAC_hash(MAC_write_secret，seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length + TLSCompressed.fragment)
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        long seqNo = readSeqNo.nextValue();
        // seq_num
        baos.write((byte) (seqNo >>> 56));
        baos.write((byte) (seqNo >>> 48));
        baos.write((byte) (seqNo >>> 40));
        baos.write((byte) (seqNo >>> 32));
        baos.write((byte) (seqNo >>> 24));
        baos.write((byte) (seqNo >>> 16));
        baos.write((byte) (seqNo >>> 8));
        baos.write((byte) (seqNo));
        // type
        baos.write(record.contentType.getValue());
        // version
        baos.write(record.version.getMajor());
        baos.write(record.version.getMinor());
        // length
        baos.write(content.length >>> 8 & 0xFF);
        baos.write(content.length & 0xFF);
        // fragment
        baos.write(content);
        byte[] mac = hmacHash(baos.toByteArray(), serverMacKey);
        if (!Arrays.equals(serverMac, mac)) {
            Alert alert = new Alert(Alert.Level.FATAL, Alert.Description.BAD_RECORD_MAC);
            throw new AlertException(alert, false);
        }

        return content;
    }

    public Record encrypt(Record record) throws IOException {
        // HMAC_hash(MAC_write_secret，seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length + TLSCompressed.fragment)
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        long seqNo = writeSeqNo.nextValue();
        // seq_num: 序列号。每一个读写状态都分别维持一个单调递增序列号。
        // 序列号的类型为 uint64，序列号初始值为零，最大不能超出 2^64-1。
        // 序列号不能回绕。如果序列号溢出，那就必须重新开始握手。
        baos.write((byte) (seqNo >>> 56));
        baos.write((byte) (seqNo >>> 48));
        baos.write((byte) (seqNo >>> 40));
        baos.write((byte) (seqNo >>> 32));
        baos.write((byte) (seqNo >>> 24));
        baos.write((byte) (seqNo >>> 16));
        baos.write((byte) (seqNo >>> 8));
        baos.write((byte) (seqNo));
        // type
        baos.write(record.contentType.getValue());
        // version
        baos.write(record.version.getMajor());
        baos.write(record.version.getMinor());
        // length
        baos.write(record.fragment.length >>> 8 & 0xFF);
        baos.write(record.fragment.length & 0xFF);
        // fragment
        baos.write(record.fragment);
        byte[] data = baos.toByteArray();
        byte[] mac = hmacHash(data, clientMacKey);

        ByteArrayOutputStream block = new ByteArrayOutputStream();
        // iv
        block.write(clientWriteIV);
        // content
        block.write(record.fragment);
        // mac
        block.write(mac);

        byte[] encrypted2 = encryptByCbc(writeEngine, block.toByteArray());
        byte[] encrypted;
        if (true) {

            // padding length, the 1 is "padding length" size
            int total = clientWriteIV.length + record.fragment.length + mac.length + 1;
            int paddingLength = BLOCK_SIZE - total % BLOCK_SIZE;
            block.write(paddingLength);
            // padding
            for (int i = 0; i < paddingLength; i++) {
                block.write(paddingLength);
            }
            encrypted = encrypt(block.toByteArray(), writeCipher, clientWriteIV);
        }

        return new Record(record.contentType, record.version, encrypted2);
//         iv, content, mac, padding length, padding
    }

    private static byte[] encrypt(byte[] bytes, SM4Engine engine, byte[] iv) {
        byte[] out = new byte[bytes.length];
        int times = bytes.length / BLOCK_SIZE;
        byte[] tmp = new byte[BLOCK_SIZE];
        byte[] IVTmp = new byte[BLOCK_SIZE];

        System.arraycopy(iv, 0, IVTmp, 0, BLOCK_SIZE);

        for (int i = 0; i < times; i++) {
            for (int j = 0; j < BLOCK_SIZE; j++) {
                tmp[j] = (byte) (IVTmp[j] ^ bytes[i * BLOCK_SIZE + j]);
            }
            engine.processBlock(tmp, 0, out, i * BLOCK_SIZE);
            System.arraycopy(out, i * BLOCK_SIZE, IVTmp, 0, BLOCK_SIZE);
        }
        return out;
    }

    private static byte[] encryptByCbc(PaddedBufferedBlockCipher cipher, byte[] plainBytes) {
        try {
            // 加密
            int updateOutputSize = cipher.getOutputSize(plainBytes.length);
            byte[] out = new byte[updateOutputSize];
            int len = cipher.processBytes(plainBytes, 0, plainBytes.length, out, 0);
            cipher.doFinal(out, len);

            return out;
        } catch (Exception e) {
            throw new RuntimeException("encrypt error", e);
        }
    }

    private static byte[] decryptByCbc(PaddedBufferedBlockCipher cipher, byte[] cipherBytes) {
        try {
            // 解密
            int updateOutputSize = cipher.getOutputSize(cipherBytes.length);
            byte[] buf = new byte[updateOutputSize];
            int len = cipher.processBytes(cipherBytes, 0, cipherBytes.length, buf, 0);
            len += cipher.doFinal(buf, len);

            // 移除 Padding
            byte[] out = new byte[len];
            System.arraycopy(buf, 0, out, 0, len);
            return out;
        } catch (Exception e) {
            throw new RuntimeException("decrypt error", e);
        }
    }

    private static byte[] decrypt(byte[] encrypted, SM4Engine engine, byte[] iv) {
        byte[] decrypted = new byte[encrypted.length];
        int BLOCK_SIZE = 16;
        int times = encrypted.length / BLOCK_SIZE;

        byte[] tmp = new byte[BLOCK_SIZE];

        byte[] IVTmp = new byte[BLOCK_SIZE];
        System.arraycopy(iv, 0, IVTmp, 0, BLOCK_SIZE);

        for (int i = 0; i < times; i++) {
            byte[] in = new byte[BLOCK_SIZE];
            System.arraycopy(encrypted, i * BLOCK_SIZE, in, 0, BLOCK_SIZE);
            System.arraycopy(encrypted, i * BLOCK_SIZE, tmp, 0, BLOCK_SIZE);
            byte[] tmpOut = new byte[BLOCK_SIZE];
            // 解密一块到 tmpOut
            engine.processBlock(in, 0, tmpOut, 0);
            byte[] out = new byte[BLOCK_SIZE];
            for (int j = 0; j < BLOCK_SIZE; j++) {
                out[j] = (byte) (tmpOut[j] ^ IVTmp[j]);
            }

            System.arraycopy(tmp, 0, IVTmp, 0, BLOCK_SIZE);

            System.arraycopy(out, 0, decrypted, i * BLOCK_SIZE, BLOCK_SIZE);
        }
        return decrypted;
    }

    private static byte[] hmacHash(byte[] data, byte[] secret) {
        KeyParameter keyParameter = new KeyParameter(secret);
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);
        mac.update(data, 0, data.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    public void flush() throws IOException {
        output.flush();
    }

    private static class SequenceNumber {
        private long value = 0L;
        private boolean exhausted = false;

        synchronized long nextValue() throws AlertException {
            // if (exhausted)
            // {
            // throw new AlertException();
            // }
            long result = value;
            if (++value == 0) {
                exhausted = true;
            }
            return result;
        }
    }

}
