package com.aliyun.gmsse;

/**
 * 记录层将数据分成 2^14 字节或者更小的片段。
 * 每个片段结构如下：
 * <pre>
 * struct {
 *     ContentType type;
 *     ProtocolVersion version;
 *     uint16 length;
 *     opaque fragment[TLSPlaintext.length]
 * } TLSPlaintext;
 */
public class Record {
    /**
     * 片段的记录层协议类型
     */
    ContentType contentType;

    /**
     * 所用协议的版本号
     * 本标准的版本号为 1.1
     */
    ProtocolVersion version;
    /**
     * 将传输的数据
     * 记录层协议不关心具体数据内容
     */
    public byte[] fragment;

    public Record(ContentType contentType, ProtocolVersion version, byte[] fragment) {
        this.contentType = contentType;
        this.version = version;
        this.fragment = fragment;
    }

    /**
     * ContentType: 片段的记录层协议类型。定义为：
     * <pre>
     * enum {
     *     change_cipher_spec(20),
     *     alert(21),
     *     handshake(22),
     *     application_data(23),
     *     site2site(80),
     *     (255)
     * } ContentType;
     */
    public static class ContentType {
        final public static ContentType CHANGE_CIPHER_SPEC = new ContentType(20, "change_cipher_spec");
        final public static ContentType ALERT = new ContentType(21, "alert");
        final public static ContentType HANDSHAKE = new ContentType(22, "handshake");
        final public static ContentType APPLICATION_DATA = new ContentType(23, "application_data");
        final public static ContentType SITE2SITE = new ContentType(80, "site2site");
        final private int value;
        final private String name;

        ContentType(int value, String name) {
            this.value = value;
            this.name = name;
        }

        public static ContentType getInstance(int value) {
            switch (value) {
                case 20:
                    return CHANGE_CIPHER_SPEC;
                case 21:
                    return ALERT;
                case 22:
                    return HANDSHAKE;
                case 23:
                    return APPLICATION_DATA;
                case 24:
                    return SITE2SITE;
            }
            return new ContentType(value, "unknown content type");
        }

        public String toString() {
            return "content type: " + name;
        }

        public int getValue() {
            return value;
        }
    }
}