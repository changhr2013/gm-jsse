package com.aliyun.gmsse;

/**
 * 用于数据压缩的算法
 * 所有的记录都是用当前会话状态指定的压缩算法进行压缩。当前会话状态指定的压缩算法被初始化为空算法。
 * 压缩算法将一个 TLSPlaintext 结构的数据转换成一个 TLSCompressed 结构的数据。
 * 压缩后的数据长度最多只能增加 1024 个字节。如果解压缩后的数据长度超过了 2^14 个字节，则报告一个 decompression failure 致命错误。
 * 压缩后的数据结构如下：
 * <pre>
 * struct {
 *     ContentType type;
 *     ProtocolVersion version;
 *     uint16 length;
 *     opaque fragment[TLSCompressed.length];
 * } TLSCompressed;
 * </pre>
 */
public class CompressionMethod {

    private final int value;

    public CompressionMethod(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    @Override
    public String toString() {
        switch (value) {
            case 0:
                return "null";
            case 1:
                return "zlib";
            default:
                return "unknown(" + value + ")";
        }
    }

    static final CompressionMethod NULL = new CompressionMethod(0);
    static final CompressionMethod ZLIB = new CompressionMethod(1);

    public static CompressionMethod getInstance(int value) {
        switch (value) {
            case 0:
                return NULL;
            case 1:
                return ZLIB;
            default:
                return new CompressionMethod(value);
        }
    }
}
