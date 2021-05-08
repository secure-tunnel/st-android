package com.bankcomm.bmf.security;


/**
 * 混淆模式
 */
public class MixedModel {

    private static final int MIXED_MATRIX_T_L = 9;
    private static final int MIXED_MATRIX_F_L = 16;
    private static final int MIXED_MATRIX_D_L = 18;

    private static final int mixed_matrix1[] = {4, 6, 0, 3, 0, 2, 7, 8, 0};
    private static final int mixed_matrix2[] = {-8, 0, 6, 7, 0, -4, 12, 5, -9};


    private static byte[] switchmodel(byte[] data) {
        byte[] tmp = new byte[data.length];
        System.arraycopy(data, 0, tmp, 0, data.length);
        for (int i = 0; i < tmp.length / 2; i++) {
            byte t = tmp[i];
            tmp[i] = tmp[tmp.length - 1 - i];
            tmp[tmp.length - 1 - i] = t;
        }
        return tmp;
    }

    private static byte[] xor(byte[] data) {
        byte[] tmp = new byte[data.length];
        System.arraycopy(data, 0, tmp, 0, data.length);
        for (int i = 0; i < data.length; i++) {
            tmp[i] ^= 0x39;
        }
        return tmp;
    }

    private static byte[] matrix_t_refra(byte[] data) {
        int slen = data.length % MIXED_MATRIX_T_L == 0 ? data.length : (data.length / MIXED_MATRIX_T_L + 1) * MIXED_MATRIX_T_L;
        byte[] t_data = new byte[slen];
        System.arraycopy(data, 0, t_data, 0, data.length);

        byte[] buffer = new byte[slen + 4];
        System.arraycopy(SafeUtil.Int2BytesBigEndian(data.length), 0, buffer, 0, 4);
        int offset = 4;
        for (int i = 0; i < t_data.length / MIXED_MATRIX_T_L; i++) {
            buffer[i * MIXED_MATRIX_T_L + offset] = t_data[i * MIXED_MATRIX_T_L + 8];
            buffer[i * MIXED_MATRIX_T_L + offset + 1] = t_data[i * MIXED_MATRIX_T_L + 5];
            buffer[i * MIXED_MATRIX_T_L + offset + 2] = t_data[i * MIXED_MATRIX_T_L + 2];
            buffer[i * MIXED_MATRIX_T_L + offset + 3] = t_data[i * MIXED_MATRIX_T_L + 7];
            buffer[i * MIXED_MATRIX_T_L + offset + 4] = t_data[i * MIXED_MATRIX_T_L + 4];
            buffer[i * MIXED_MATRIX_T_L + offset + 5] = t_data[i * MIXED_MATRIX_T_L + 1];
            buffer[i * MIXED_MATRIX_T_L + offset + 6] = t_data[i * MIXED_MATRIX_T_L + 6];
            buffer[i * MIXED_MATRIX_T_L + offset + 7] = t_data[i * MIXED_MATRIX_T_L + 3];
            buffer[i * MIXED_MATRIX_T_L + offset + 8] = t_data[i * MIXED_MATRIX_T_L];
        }
        return buffer;
    }

    private static byte[] reverse_matrix_t_refra(byte[] data) {
        byte[] buffer = new byte[data.length - 4];
        System.arraycopy(data, 4, buffer, 0, data.length - 4);

        int offset = 4;
        for (int i = 0; i < (data.length - 4) / MIXED_MATRIX_T_L; i++) {
            buffer[i * MIXED_MATRIX_T_L] = data[offset + 8];
            buffer[i * MIXED_MATRIX_T_L + 1] = data[offset + 5];
            buffer[i * MIXED_MATRIX_T_L + 2] = data[offset + 2];
            buffer[i * MIXED_MATRIX_T_L + 3] = data[offset + 7];
            buffer[i * MIXED_MATRIX_T_L + 4] = data[offset + 4];
            buffer[i * MIXED_MATRIX_T_L + 5] = data[offset + 1];
            buffer[i * MIXED_MATRIX_T_L + 6] = data[offset + 6];
            buffer[i * MIXED_MATRIX_T_L + 7] = data[offset + 3];
            buffer[i * MIXED_MATRIX_T_L + 8] = data[offset];
            offset += MIXED_MATRIX_T_L;
        }
        int oldLen = SafeUtil.BytesBigEndian2Int(data);
        byte[] buffer0 = new byte[oldLen];
        System.arraycopy(buffer, 0, buffer0, 0, oldLen);
        return buffer0;
    }

    private static byte[] matrix_t_refra_re(byte[] data) {
        int slen = data.length % MIXED_MATRIX_T_L == 0 ? data.length : (data.length / MIXED_MATRIX_T_L + 1) * MIXED_MATRIX_T_L;
        byte[] t_data = new byte[slen];
        System.arraycopy(data, 0, t_data, 0, data.length);

        byte[] buffer = new byte[slen + 4];
        System.arraycopy(SafeUtil.Int2BytesBigEndian(data.length), 0, buffer, 0, 4);
        int offset = 4;
        for (int i = 0; i < t_data.length / MIXED_MATRIX_T_L; i++) {
            buffer[i * MIXED_MATRIX_T_L+offset] = t_data[i * MIXED_MATRIX_T_L];
            buffer[i * MIXED_MATRIX_T_L +offset+ 1] = t_data[i * MIXED_MATRIX_T_L + 3];
            buffer[i * MIXED_MATRIX_T_L+offset + 2] = t_data[i * MIXED_MATRIX_T_L + 6];
            buffer[i * MIXED_MATRIX_T_L+offset + 3] = t_data[i * MIXED_MATRIX_T_L + 1];
            buffer[i * MIXED_MATRIX_T_L+offset + 4] = t_data[i * MIXED_MATRIX_T_L + 4];
            buffer[i * MIXED_MATRIX_T_L+offset + 5] = t_data[i * MIXED_MATRIX_T_L + 7];
            buffer[i * MIXED_MATRIX_T_L+offset + 6] = t_data[i * MIXED_MATRIX_T_L + 2];
            buffer[i * MIXED_MATRIX_T_L+offset + 7] = t_data[i * MIXED_MATRIX_T_L + 5];
            buffer[i * MIXED_MATRIX_T_L+offset + 8] = t_data[i * MIXED_MATRIX_T_L + 8];
        }
        return buffer;
    }

    private static byte[] reverse_matrix_t_refra_re(byte[] data) {
        byte[] buffer = new byte[data.length - 4];
        System.arraycopy(data, 4, buffer, 0, data.length - 4);

        int offset = 4;
        for (int i = 0; i < (data.length - 4) / MIXED_MATRIX_T_L; i++) {
            buffer[i * MIXED_MATRIX_T_L] = data[offset];
            buffer[i * MIXED_MATRIX_T_L + 1] = data[offset + 3];
            buffer[i * MIXED_MATRIX_T_L + 2] = data[offset + 6];
            buffer[i * MIXED_MATRIX_T_L + 3] = data[offset + 1];
            buffer[i * MIXED_MATRIX_T_L + 4] = data[offset + 4];
            buffer[i * MIXED_MATRIX_T_L + 5] = data[offset + 7];
            buffer[i * MIXED_MATRIX_T_L + 6] = data[offset + 2];
            buffer[i * MIXED_MATRIX_T_L + 7] = data[offset + 5];
            buffer[i * MIXED_MATRIX_T_L + 8] = data[offset + 8];
            offset += MIXED_MATRIX_T_L;
        }
        int oldLen = SafeUtil.BytesBigEndian2Int(data);
        byte[] buffer0 = new byte[oldLen];
        System.arraycopy(buffer, 0, buffer0, 0, oldLen);
        return buffer0;
    }

    private static byte[] matrix_t_row(byte[] data) {
        int slen = data.length % MIXED_MATRIX_T_L == 0 ? data.length : (data.length / MIXED_MATRIX_T_L + 1) * MIXED_MATRIX_T_L;
        byte[] t_data = new byte[slen];
        System.arraycopy(data, 0, t_data, 0, data.length);

        byte[] buffer = new byte[slen + 4];
        System.arraycopy(SafeUtil.Int2BytesBigEndian(data.length), 0, buffer, 0, 4);
        int offset = 4;
        for (int i = 0; i < t_data.length / MIXED_MATRIX_T_L; i++) {
            buffer[i * MIXED_MATRIX_T_L+offset] = t_data[i * MIXED_MATRIX_T_L + 3];
            buffer[i * MIXED_MATRIX_T_L+offset + 1] = t_data[i * MIXED_MATRIX_T_L + 4];
            buffer[i * MIXED_MATRIX_T_L +offset+ 2] = t_data[i * MIXED_MATRIX_T_L + 5];
            buffer[i * MIXED_MATRIX_T_L+offset + 3] = t_data[i * MIXED_MATRIX_T_L + 6];
            buffer[i * MIXED_MATRIX_T_L+offset + 4] = t_data[i * MIXED_MATRIX_T_L + 7];
            buffer[i * MIXED_MATRIX_T_L +offset+ 5] = t_data[i * MIXED_MATRIX_T_L + 8];
            buffer[i * MIXED_MATRIX_T_L+offset + 6] = t_data[i * MIXED_MATRIX_T_L];
            buffer[i * MIXED_MATRIX_T_L+offset + 7] = t_data[i * MIXED_MATRIX_T_L + 1];
            buffer[i * MIXED_MATRIX_T_L+offset + 8] = t_data[i * MIXED_MATRIX_T_L + 2];
        }
        return buffer;
    }

    private static byte[] reverse_matrix_t_row(byte[] data) {
        byte[] buffer = new byte[data.length - 4];
        System.arraycopy(data, 4, buffer, 0, data.length - 4);

        int offset = 4;
        for (int i = 0; i < (data.length - 4) / MIXED_MATRIX_T_L; i++) {
            buffer[i * MIXED_MATRIX_T_L] = data[offset + 6];
            buffer[i * MIXED_MATRIX_T_L + 1] = data[offset + 7];
            buffer[i * MIXED_MATRIX_T_L + 2] = data[offset + 8];
            buffer[i * MIXED_MATRIX_T_L + 3] = data[offset];
            buffer[i * MIXED_MATRIX_T_L + 4] = data[offset + 1];
            buffer[i * MIXED_MATRIX_T_L + 5] = data[offset + 2];
            buffer[i * MIXED_MATRIX_T_L + 6] = data[offset + 3];
            buffer[i * MIXED_MATRIX_T_L + 7] = data[offset + 4];
            buffer[i * MIXED_MATRIX_T_L + 8] = data[offset + 5];
            offset += MIXED_MATRIX_T_L;
        }
        int oldLen = SafeUtil.BytesBigEndian2Int(data);
        byte[] buffer0 = new byte[oldLen];
        System.arraycopy(buffer, 0, buffer0, 0, oldLen);
        return buffer0;
    }

    private static byte[] matrix_t_col(byte[] data) {
        int slen = data.length % MIXED_MATRIX_T_L == 0 ? data.length : (data.length / MIXED_MATRIX_T_L + 1) * MIXED_MATRIX_T_L;
        byte[] t_data = new byte[slen];
        System.arraycopy(data, 0, t_data, 0, data.length);

        byte[] buffer = new byte[slen + 4];
        System.arraycopy(SafeUtil.Int2BytesBigEndian(data.length), 0, buffer, 0, 4);
        int offset = 4;
        for (int i = 0; i < t_data.length / MIXED_MATRIX_T_L; i++) {
            buffer[i * MIXED_MATRIX_T_L+offset] = t_data[i * MIXED_MATRIX_T_L + 1];
            buffer[i * MIXED_MATRIX_T_L+offset + 1] = t_data[i * MIXED_MATRIX_T_L + 2];
            buffer[i * MIXED_MATRIX_T_L+offset + 2] = t_data[i * MIXED_MATRIX_T_L];
            buffer[i * MIXED_MATRIX_T_L+offset + 3] = t_data[i * MIXED_MATRIX_T_L + 4];
            buffer[i * MIXED_MATRIX_T_L+offset + 4] = t_data[i * MIXED_MATRIX_T_L + 5];
            buffer[i * MIXED_MATRIX_T_L+offset + 5] = t_data[i * MIXED_MATRIX_T_L + 3];
            buffer[i * MIXED_MATRIX_T_L+offset + 6] = t_data[i * MIXED_MATRIX_T_L + 7];
            buffer[i * MIXED_MATRIX_T_L+offset + 7] = t_data[i * MIXED_MATRIX_T_L + 8];
            buffer[i * MIXED_MATRIX_T_L+offset + 8] = t_data[i * MIXED_MATRIX_T_L + 6];
        }
        return buffer;
    }

    private static byte[] reverse_matrix_t_col(byte[] data) {
        byte[] buffer = new byte[data.length - 4];
        System.arraycopy(data, 4, buffer, 0, data.length - 4);

        int offset = 4;
        for (int i = 0; i < (data.length - 4) / MIXED_MATRIX_T_L; i++) {
            buffer[i * MIXED_MATRIX_T_L] = data[offset + 2];
            buffer[i * MIXED_MATRIX_T_L + 1] = data[offset];
            buffer[i * MIXED_MATRIX_T_L + 2] = data[offset + 1];
            buffer[i * MIXED_MATRIX_T_L + 3] = data[offset + 5];
            buffer[i * MIXED_MATRIX_T_L + 4] = data[offset + 3];
            buffer[i * MIXED_MATRIX_T_L + 5] = data[offset + 4];
            buffer[i * MIXED_MATRIX_T_L + 6] = data[offset + 8];
            buffer[i * MIXED_MATRIX_T_L + 7] = data[offset + 6];
            buffer[i * MIXED_MATRIX_T_L + 8] = data[offset + 7];
            offset += MIXED_MATRIX_T_L;
        }
        int oldLen = SafeUtil.BytesBigEndian2Int(data);
        byte[] buffer0 = new byte[oldLen];
        System.arraycopy(buffer, 0, buffer0, 0, oldLen);
        return buffer0;
    }

    private static byte[] matrix_f_refra(byte[] data) {
        int slen = data.length % MIXED_MATRIX_F_L == 0 ? data.length : (data.length / MIXED_MATRIX_F_L + 1) * MIXED_MATRIX_F_L;
        byte[] t_data = new byte[slen];
        System.arraycopy(data, 0, t_data, 0, data.length);

        byte[] buffer = new byte[slen + 4];
        System.arraycopy(SafeUtil.Int2BytesBigEndian(data.length), 0, buffer, 0, 4);
        int offset = 4;
        for (int i = 0; i < t_data.length / MIXED_MATRIX_F_L; i++) {
            buffer[i * MIXED_MATRIX_F_L+offset] = t_data[i * MIXED_MATRIX_F_L + 15];
            buffer[i * MIXED_MATRIX_F_L+offset + 1] = t_data[i * MIXED_MATRIX_F_L + 11];
            buffer[i * MIXED_MATRIX_F_L+offset + 2] = t_data[i * MIXED_MATRIX_F_L + 7];
            buffer[i * MIXED_MATRIX_F_L +offset+ 3] = t_data[i * MIXED_MATRIX_F_L + 3];
            buffer[i * MIXED_MATRIX_F_L +offset+ 4] = t_data[i * MIXED_MATRIX_F_L + 14];
            buffer[i * MIXED_MATRIX_F_L+offset + 5] = t_data[i * MIXED_MATRIX_F_L + 10];
            buffer[i * MIXED_MATRIX_F_L+offset + 6] = t_data[i * MIXED_MATRIX_F_L + 6];
            buffer[i * MIXED_MATRIX_F_L+offset + 7] = t_data[i * MIXED_MATRIX_F_L + 2];
            buffer[i * MIXED_MATRIX_F_L+offset + 8] = t_data[i * MIXED_MATRIX_F_L + 13];
            buffer[i * MIXED_MATRIX_F_L+offset + 9] = t_data[i * MIXED_MATRIX_F_L + 9];
            buffer[i * MIXED_MATRIX_F_L+offset + 10] = t_data[i * MIXED_MATRIX_F_L + 5];
            buffer[i * MIXED_MATRIX_F_L+offset + 11] = t_data[i * MIXED_MATRIX_F_L + 1];
            buffer[i * MIXED_MATRIX_F_L+offset + 12] = t_data[i * MIXED_MATRIX_F_L + 12];
            buffer[i * MIXED_MATRIX_F_L+offset + 13] = t_data[i * MIXED_MATRIX_F_L + 8];
            buffer[i * MIXED_MATRIX_F_L +offset+ 14] = t_data[i * MIXED_MATRIX_F_L + 4];
            buffer[i * MIXED_MATRIX_F_L+offset + 15] = t_data[i * MIXED_MATRIX_F_L];
        }
        return buffer;
    }

    private static byte[] reverse_matrix_f_refra(byte[] data) {
        byte[] buffer = new byte[data.length - 4];
        System.arraycopy(data, 4, buffer, 0, data.length - 4);

        int offset = 4;
        for (int i = 0; i < (data.length - 4) / MIXED_MATRIX_F_L; i++) {
            buffer[i * MIXED_MATRIX_F_L] = data[offset + 15];
            buffer[i * MIXED_MATRIX_F_L + 1] = data[offset + 11];
            buffer[i * MIXED_MATRIX_F_L + 2] = data[offset + 7];
            buffer[i * MIXED_MATRIX_F_L + 3] = data[offset + 3];
            buffer[i * MIXED_MATRIX_F_L + 4] = data[offset + 14];
            buffer[i * MIXED_MATRIX_F_L + 5] = data[offset + 10];
            buffer[i * MIXED_MATRIX_F_L + 6] = data[offset + 6];
            buffer[i * MIXED_MATRIX_F_L + 7] = data[offset + 2];
            buffer[i * MIXED_MATRIX_F_L + 8] = data[offset + 13];
            buffer[i * MIXED_MATRIX_F_L + 9] = data[offset + 9];
            buffer[i * MIXED_MATRIX_F_L + 10] = data[offset + 5];
            buffer[i * MIXED_MATRIX_F_L + 11] = data[offset + 1];
            buffer[i * MIXED_MATRIX_F_L + 12] = data[offset + 12];
            buffer[i * MIXED_MATRIX_F_L + 13] = data[offset + 8];
            buffer[i * MIXED_MATRIX_F_L + 14] = data[offset + 4];
            buffer[i * MIXED_MATRIX_F_L + 15] = data[offset];
            offset += MIXED_MATRIX_F_L;
        }
        int oldLen = SafeUtil.BytesBigEndian2Int(data);
        byte[] buffer0 = new byte[oldLen];
        System.arraycopy(buffer, 0, buffer0, 0, oldLen);
        return buffer0;
    }

    private static byte[] matrix_f_refra_re(byte[] data) {
        int slen = data.length % MIXED_MATRIX_F_L == 0 ? data.length : (data.length / MIXED_MATRIX_F_L + 1) * MIXED_MATRIX_F_L;
        byte[] t_data = new byte[slen];
        System.arraycopy(data, 0, t_data, 0, data.length);

        byte[] buffer = new byte[slen + 4];
        System.arraycopy(SafeUtil.Int2BytesBigEndian(data.length), 0, buffer, 0, 4);
        int offset = 4;
        for (int i = 0; i < t_data.length / MIXED_MATRIX_F_L; i++) {
            buffer[i * MIXED_MATRIX_F_L+offset] = t_data[i * MIXED_MATRIX_F_L];
            buffer[i * MIXED_MATRIX_F_L+offset + 1] = t_data[i * MIXED_MATRIX_F_L + 4];
            buffer[i * MIXED_MATRIX_F_L+offset + 2] = t_data[i * MIXED_MATRIX_F_L + 8];
            buffer[i * MIXED_MATRIX_F_L+offset + 3] = t_data[i * MIXED_MATRIX_F_L + 12];
            buffer[i * MIXED_MATRIX_F_L+offset + 4] = t_data[i * MIXED_MATRIX_F_L + 1];
            buffer[i * MIXED_MATRIX_F_L+offset + 5] = t_data[i * MIXED_MATRIX_F_L + 5];
            buffer[i * MIXED_MATRIX_F_L+offset + 6] = t_data[i * MIXED_MATRIX_F_L + 9];
            buffer[i * MIXED_MATRIX_F_L+offset + 7] = t_data[i * MIXED_MATRIX_F_L + 13];
            buffer[i * MIXED_MATRIX_F_L+offset + 8] = t_data[i * MIXED_MATRIX_F_L + 2];
            buffer[i * MIXED_MATRIX_F_L+offset + 9] = t_data[i * MIXED_MATRIX_F_L + 6];
            buffer[i * MIXED_MATRIX_F_L+offset + 10] = t_data[i * MIXED_MATRIX_F_L + 10];
            buffer[i * MIXED_MATRIX_F_L+offset + 11] = t_data[i * MIXED_MATRIX_F_L + 14];
            buffer[i * MIXED_MATRIX_F_L+offset + 12] = t_data[i * MIXED_MATRIX_F_L + 3];
            buffer[i * MIXED_MATRIX_F_L+offset + 13] = t_data[i * MIXED_MATRIX_F_L + 7];
            buffer[i * MIXED_MATRIX_F_L+offset + 14] = t_data[i * MIXED_MATRIX_F_L + 11];
            buffer[i * MIXED_MATRIX_F_L+offset + 15] = t_data[i * MIXED_MATRIX_F_L + 15];
        }
        return buffer;
    }

    private static byte[] reverse_matrix_f_refra_re(byte[] data) {
        byte[] buffer = new byte[data.length - 4];
        System.arraycopy(data, 4, buffer, 0, data.length - 4);

        int offset = 4;
        for (int i = 0; i < (data.length - 4) / MIXED_MATRIX_F_L; i++) {
            buffer[i * MIXED_MATRIX_F_L] = data[offset];
            buffer[i * MIXED_MATRIX_F_L + 1] = data[offset + 4];
            buffer[i * MIXED_MATRIX_F_L + 2] = data[offset + 8];
            buffer[i * MIXED_MATRIX_F_L + 3] = data[offset + 12];
            buffer[i * MIXED_MATRIX_F_L + 4] = data[offset + 1];
            buffer[i * MIXED_MATRIX_F_L + 5] = data[offset + 5];
            buffer[i * MIXED_MATRIX_F_L + 6] = data[offset + 9];
            buffer[i * MIXED_MATRIX_F_L + 7] = data[offset + 13];
            buffer[i * MIXED_MATRIX_F_L + 8] = data[offset + 2];
            buffer[i * MIXED_MATRIX_F_L + 9] = data[offset + 6];
            buffer[i * MIXED_MATRIX_F_L + 10] = data[offset + 10];
            buffer[i * MIXED_MATRIX_F_L + 11] = data[offset + 14];
            buffer[i * MIXED_MATRIX_F_L + 12] = data[offset + 3];
            buffer[i * MIXED_MATRIX_F_L + 13] = data[offset + 7];
            buffer[i * MIXED_MATRIX_F_L + 14] = data[offset + 11];
            buffer[i * MIXED_MATRIX_F_L + 15] = data[offset + 15];
            offset += MIXED_MATRIX_F_L;
        }
        int oldLen = SafeUtil.BytesBigEndian2Int(data);
        byte[] buffer0 = new byte[oldLen];
        System.arraycopy(buffer, 0, buffer0, 0, oldLen);
        return buffer0;
    }

    private static byte[] matrix_f_row(byte[] data) {
        int slen = data.length % MIXED_MATRIX_F_L == 0 ? data.length : (data.length / MIXED_MATRIX_F_L + 1) * MIXED_MATRIX_F_L;
        byte[] t_data = new byte[slen];
        System.arraycopy(data, 0, t_data, 0, data.length);

        byte[] buffer = new byte[slen + 4];
        System.arraycopy(SafeUtil.Int2BytesBigEndian(data.length), 0, buffer, 0, 4);
        int offset = 4;
        for (int i = 0; i < t_data.length / MIXED_MATRIX_F_L; i++) {
            buffer[i * MIXED_MATRIX_F_L+offset] = t_data[i * MIXED_MATRIX_F_L + 4];
            buffer[i * MIXED_MATRIX_F_L+offset + 1] = t_data[i * MIXED_MATRIX_F_L + 5];
            buffer[i * MIXED_MATRIX_F_L+offset + 2] = t_data[i * MIXED_MATRIX_F_L + 6];
            buffer[i * MIXED_MATRIX_F_L +offset+ 3] = t_data[i * MIXED_MATRIX_F_L + 7];
            buffer[i * MIXED_MATRIX_F_L +offset+ 4] = t_data[i * MIXED_MATRIX_F_L + 8];
            buffer[i * MIXED_MATRIX_F_L +offset+ 5] = t_data[i * MIXED_MATRIX_F_L + 9];
            buffer[i * MIXED_MATRIX_F_L+offset + 6] = t_data[i * MIXED_MATRIX_F_L + 10];
            buffer[i * MIXED_MATRIX_F_L+offset + 7] = t_data[i * MIXED_MATRIX_F_L + 11];
            buffer[i * MIXED_MATRIX_F_L+offset + 8] = t_data[i * MIXED_MATRIX_F_L + 12];
            buffer[i * MIXED_MATRIX_F_L+offset + 9] = t_data[i * MIXED_MATRIX_F_L + 13];
            buffer[i * MIXED_MATRIX_F_L+offset + 10] = t_data[i * MIXED_MATRIX_F_L + 14];
            buffer[i * MIXED_MATRIX_F_L+offset + 11] = t_data[i * MIXED_MATRIX_F_L + 15];
            buffer[i * MIXED_MATRIX_F_L +offset+ 12] = t_data[i * MIXED_MATRIX_F_L];
            buffer[i * MIXED_MATRIX_F_L+offset + 13] = t_data[i * MIXED_MATRIX_F_L + 1];
            buffer[i * MIXED_MATRIX_F_L+offset + 14] = t_data[i * MIXED_MATRIX_F_L + 2];
            buffer[i * MIXED_MATRIX_F_L+offset + 15] = t_data[i * MIXED_MATRIX_F_L + 3];
        }
        return buffer;
    }

    private static byte[] reverse_matrix_f_row(byte[] data) {
        byte[] buffer = new byte[data.length - 4];
        System.arraycopy(data, 4, buffer, 0, data.length - 4);

        int offset = 4;
        for (int i = 0; i < (data.length - 4) / MIXED_MATRIX_F_L; i++) {
            buffer[i * MIXED_MATRIX_F_L] = data[offset + 12];
            buffer[i * MIXED_MATRIX_F_L + 1] = data[offset + 13];
            buffer[i * MIXED_MATRIX_F_L + 2] = data[offset + 14];
            buffer[i * MIXED_MATRIX_F_L + 3] = data[offset + 15];
            buffer[i * MIXED_MATRIX_F_L + 4] = data[offset];
            buffer[i * MIXED_MATRIX_F_L + 5] = data[offset + 1];
            buffer[i * MIXED_MATRIX_F_L + 6] = data[offset + 2];
            buffer[i * MIXED_MATRIX_F_L + 7] = data[offset + 3];
            buffer[i * MIXED_MATRIX_F_L + 8] = data[offset + 4];
            buffer[i * MIXED_MATRIX_F_L + 9] = data[offset + 5];
            buffer[i * MIXED_MATRIX_F_L + 10] = data[offset + 6];
            buffer[i * MIXED_MATRIX_F_L + 11] = data[offset + 7];
            buffer[i * MIXED_MATRIX_F_L + 12] = data[offset + 8];
            buffer[i * MIXED_MATRIX_F_L + 13] = data[offset + 9];
            buffer[i * MIXED_MATRIX_F_L + 14] = data[offset + 10];
            buffer[i * MIXED_MATRIX_F_L + 15] = data[offset + 11];
            offset += MIXED_MATRIX_F_L;
        }
        int oldLen = SafeUtil.BytesBigEndian2Int(data);
        byte[] buffer0 = new byte[oldLen];
        System.arraycopy(buffer, 0, buffer0, 0, oldLen);
        return buffer0;
    }

    private static byte[] matrix_f_col(byte[] data) {
        int slen = data.length % MIXED_MATRIX_F_L == 0 ? data.length : (data.length / MIXED_MATRIX_F_L + 1) * MIXED_MATRIX_F_L;
        byte[] t_data = new byte[slen];
        System.arraycopy(data, 0, t_data, 0, data.length);

        byte[] buffer = new byte[slen + 4];
        System.arraycopy(SafeUtil.Int2BytesBigEndian(data.length), 0, buffer, 0, 4);
        int offset = 4;
        for (int i = 0; i < t_data.length / MIXED_MATRIX_F_L; i++) {
            buffer[i * MIXED_MATRIX_F_L+offset] = t_data[i * MIXED_MATRIX_F_L + 1];
            buffer[i * MIXED_MATRIX_F_L+offset + 1] = t_data[i * MIXED_MATRIX_F_L + 2];
            buffer[i * MIXED_MATRIX_F_L+offset + 2] = t_data[i * MIXED_MATRIX_F_L + 3];
            buffer[i * MIXED_MATRIX_F_L+offset + 3] = t_data[i * MIXED_MATRIX_F_L + 0];
            buffer[i * MIXED_MATRIX_F_L+offset + 4] = t_data[i * MIXED_MATRIX_F_L + 5];
            buffer[i * MIXED_MATRIX_F_L+offset + 5] = t_data[i * MIXED_MATRIX_F_L + 6];
            buffer[i * MIXED_MATRIX_F_L+offset + 6] = t_data[i * MIXED_MATRIX_F_L + 7];
            buffer[i * MIXED_MATRIX_F_L+offset + 7] = t_data[i * MIXED_MATRIX_F_L + 4];
            buffer[i * MIXED_MATRIX_F_L+offset + 8] = t_data[i * MIXED_MATRIX_F_L + 9];
            buffer[i * MIXED_MATRIX_F_L+offset + 9] = t_data[i * MIXED_MATRIX_F_L + 10];
            buffer[i * MIXED_MATRIX_F_L+offset + 10] = t_data[i * MIXED_MATRIX_F_L + 11];
            buffer[i * MIXED_MATRIX_F_L+offset + 11] = t_data[i * MIXED_MATRIX_F_L + 8];
            buffer[i * MIXED_MATRIX_F_L+offset + 12] = t_data[i * MIXED_MATRIX_F_L + 13];
            buffer[i * MIXED_MATRIX_F_L+offset + 13] = t_data[i * MIXED_MATRIX_F_L + 14];
            buffer[i * MIXED_MATRIX_F_L+offset + 14] = t_data[i * MIXED_MATRIX_F_L + 15];
            buffer[i * MIXED_MATRIX_F_L+offset + 15] = t_data[i * MIXED_MATRIX_F_L + 12];
        }
        return buffer;
    }

    private static byte[] reverse_matrix_f_col(byte[] data) {
        byte[] buffer = new byte[data.length - 4];
        System.arraycopy(data, 4, buffer, 0, data.length - 4);

        int offset = 4;
        for (int i = 0; i < (data.length - 4) / MIXED_MATRIX_F_L; i++) {
            buffer[i * MIXED_MATRIX_F_L] = data[offset + 3];
            buffer[i * MIXED_MATRIX_F_L + 1] = data[offset];
            buffer[i * MIXED_MATRIX_F_L + 2] = data[offset + 1];
            buffer[i * MIXED_MATRIX_F_L + 3] = data[offset + 2];
            buffer[i * MIXED_MATRIX_F_L + 4] = data[offset + 7];
            buffer[i * MIXED_MATRIX_F_L + 5] = data[offset + 4];
            buffer[i * MIXED_MATRIX_F_L + 6] = data[offset + 5];
            buffer[i * MIXED_MATRIX_F_L + 7] = data[offset + 6];
            buffer[i * MIXED_MATRIX_F_L + 8] = data[offset + 11];
            buffer[i * MIXED_MATRIX_F_L + 9] = data[offset + 8];
            buffer[i * MIXED_MATRIX_F_L + 10] = data[offset + 9];
            buffer[i * MIXED_MATRIX_F_L + 11] = data[offset + 10];
            buffer[i * MIXED_MATRIX_F_L + 12] = data[offset + 15];
            buffer[i * MIXED_MATRIX_F_L + 13] = data[offset + 12];
            buffer[i * MIXED_MATRIX_F_L + 14] = data[offset + 13];
            buffer[i * MIXED_MATRIX_F_L + 15] = data[offset + 14];
            offset += MIXED_MATRIX_F_L;
        }
        int oldLen = SafeUtil.BytesBigEndian2Int(data);
        byte[] buffer0 = new byte[oldLen];
        System.arraycopy(buffer, 0, buffer0, 0, oldLen);
        return buffer0;
    }

    private static byte[] netfestival(byte[] data) {
        byte[] buffer = new byte[data.length];
        System.arraycopy(data, 0, buffer, 0, data.length);
        int t = data.length > 0x80 ? data.length ^ 0x80 : data.length;
        for (int i = 1; i <= data.length; i++) {
            if ((i & 0x0f) == 0x01 || (i & 0x0f) == 0x02 || (i & 0x0f) == 0x06 || (i & 0x0f) == 0x08 || i % 6 == 0 || i % 8 == 0 || i % 11 == 0 || i % 12 == 0) {
                buffer[i - 1] ^= (byte) t;
            }
        }
        return buffer;
    }

    private static byte[] reversibleMatrixCore1(byte[] data, int[] matrix) {
        byte[] dst = new byte[18];

        int a11 = data[0];
        int a12 = data[1];
        int a13 = data[2];
        int a21 = data[3];
        int a22 = data[4];
        int a23 = data[5];
        int a31 = data[6];
        int a32 = data[7];
        int a33 = data[8];

        int c11 = matrix[0] * a11 + matrix[1] * a21 + matrix[2] * a31;
        int c12 = matrix[0] * a12 + matrix[1] * a22 + matrix[2] * a32;
        int c13 = matrix[0] * a13 + matrix[1] * a23 + matrix[2] * a33;
        int c21 = matrix[3] * a11 + matrix[4] * a21 + matrix[5] * a31;
        int c22 = matrix[3] * a12 + matrix[4] * a22 + matrix[5] * a32;
        int c23 = matrix[3] * a13 + matrix[4] * a23 + matrix[5] * a33;
        int c31 = matrix[6] * a11 + matrix[7] * a21 + matrix[8] * a31;
        int c32 = matrix[6] * a12 + matrix[7] * a22 + matrix[8] * a32;
        int c33 = matrix[6] * a13 + matrix[7] * a23 + matrix[8] * a33;

        dst[0] = (byte) (c11 / 100);
        dst[1] = (byte) (c11 % 100);
        dst[2] = (byte) (c12 / 100);
        dst[3] = (byte) (c12 % 100);
        dst[4] = (byte) (c13 / 100);
        dst[5] = (byte) (c13 % 100);
        dst[6] = (byte) (c21 / 100);
        dst[7] = (byte) (c21 % 100);
        dst[8] = (byte) (c22 / 100);
        dst[9] = (byte) (c22 % 100);
        dst[10] = (byte) (c23 / 100);
        dst[11] = (byte) (c23 % 100);
        dst[12] = (byte) (c31 / 100);
        dst[13] = (byte) (c31 % 100);
        dst[14] = (byte) (c32 / 100);
        dst[15] = (byte) (c32 % 100);
        dst[16] = (byte) (c33 / 100);
        dst[17] = (byte) (c33 % 100);

        return dst;
    }

    private static byte[] reversibleMatrixCore2(byte[] src, int[] matrix) {
        byte[] dst = new byte[9];

        int a11 = src[0] * 100 + src[1];
        int a12 = src[2] * 100 + src[3];
        int a13 = src[4] * 100 + src[5];
        int a21 = src[6] * 100 + src[7];
        int a22 = src[8] * 100 + src[9];
        int a23 = src[10] * 100 + src[11];
        int a31 = src[12] * 100 + src[13];
        int a32 = src[14] * 100 + src[15];
        int a33 = src[16] * 100 + src[17];

        int c11 = matrix[0] * a11 + matrix[1] * a21 + matrix[2] * a31;
        int c12 = matrix[0] * a12 + matrix[1] * a22 + matrix[2] * a32;
        int c13 = matrix[0] * a13 + matrix[1] * a23 + matrix[2] * a33;
        int c21 = matrix[3] * a11 + matrix[4] * a21 + matrix[5] * a31;
        int c22 = matrix[3] * a12 + matrix[4] * a22 + matrix[5] * a32;
        int c23 = matrix[3] * a13 + matrix[4] * a23 + matrix[5] * a33;
        int c31 = matrix[6] * a11 + matrix[7] * a21 + matrix[8] * a31;
        int c32 = matrix[6] * a12 + matrix[7] * a22 + matrix[8] * a32;
        int c33 = matrix[6] * a13 + matrix[7] * a23 + matrix[8] * a33;

        dst[0] = (byte) (c11 / 10);
        dst[1] = (byte) (c12 / 10);
        dst[2] = (byte) (c13 / 10);
        dst[3] = (byte) (c21 / 10);
        dst[4] = (byte) (c22 / 10);
        dst[5] = (byte) (c23 / 10);
        dst[6] = (byte) (c31 / 10);
        dst[7] = (byte) (c32 / 10);
        dst[8] = (byte) (c33 / 10);

        return dst;
    }

    private static byte[] reversibleMatrix(byte[] data) {
        int slen = data.length % MIXED_MATRIX_T_L == 0 ? data.length : (data.length / MIXED_MATRIX_T_L + 1) * MIXED_MATRIX_T_L;
        byte[] src = new byte[slen];
        System.arraycopy(data, 0, src, 0, data.length);
        byte[] buffer = new byte[4 + slen / MIXED_MATRIX_T_L * MIXED_MATRIX_D_L];
        byte[] lenBuffer = SafeUtil.Int2BytesBigEndian(data.length);
        System.arraycopy(lenBuffer, 0, buffer, 0, 4);
        for (int i = 0; i < slen / MIXED_MATRIX_T_L; i++) {
            byte[] temp = new byte[MIXED_MATRIX_T_L];
            System.arraycopy(src, i * MIXED_MATRIX_T_L, temp, 0, MIXED_MATRIX_T_L);
            byte[] t = reversibleMatrixCore1(temp, mixed_matrix1);
            System.arraycopy(temp, 0, buffer, i * MIXED_MATRIX_D_L + 4, MIXED_MATRIX_D_L);
        }
        return buffer;
    }

    private static byte[] reverse_reversibleMatrix(byte[] data) {
        int oldLen = SafeUtil.BytesBigEndian2Int(data);
        byte[] buffer = new byte[(data.length - 4) / MIXED_MATRIX_D_L * MIXED_MATRIX_T_L];
        for (int i = 0; i < (data.length - 4) / MIXED_MATRIX_D_L; i++) {
            byte[] temp = new byte[MIXED_MATRIX_D_L];
            System.arraycopy(data, i * MIXED_MATRIX_D_L + 4, temp, 0, MIXED_MATRIX_D_L);
            byte[] t = reversibleMatrixCore2(temp, mixed_matrix2);
            System.arraycopy(temp, 0, buffer, i * MIXED_MATRIX_T_L, MIXED_MATRIX_T_L);
        }
        byte[] result = new byte[oldLen];
        System.arraycopy(buffer, 0, result, 0, oldLen);
        return result;
    }

    private static byte[] movebit(byte[] data) {
        byte[] buffer = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            byte v = data[i];
            buffer[i] = (byte) (((v & 0xff) >>> 4) ^ (v << 4));
        }
        return buffer;
    }

    private static byte[] movebit2_core(byte[] data, boolean oper) {
        byte[] buffer = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            byte v = data[i];
            if (oper) {
                buffer[i] = (byte) (((v & 0xff) >>> 4 ^ 0x05) ^ (v << 4));
            } else {
                buffer[i] = (byte) (((v & 0xff) >>> 4) ^ (v << 4 ^ 80));
            }
        }
        return buffer;
    }

    private static byte[] movebit2(byte[] data) {
        return movebit2_core(data, true);
    }

    private static byte[] reverse_movebit2(byte[] data) {
        return movebit2_core(data, false);
    }

    private static byte[] movebit3(byte[] data) {
        byte[] buffer = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            byte v = data[i];
            byte t1 = (byte) (((v << (2 - 1)) & 0xff) >>> 7);
            byte t2 = (byte) (((v << (3 - 1)) & 0xff) >>> 7);
            byte t3 = (byte) (((v << (6 - 1)) & 0xff) >>> 7);
            byte t4 = (byte) (((v << (7 - 1)) & 0xff) >>> 7);
            if (t1 == 0 && t3 == 1) {
                v = (byte) (v + (1 << (8 - 2)) - (1 << (8 - 6)));
            }
            if (t1 == 1 && t3 == 0) {
                v = (byte) (v - (1 << (8 - 2)) + (1 << (8 - 6)));
            }
            if (t2 == 0 && t4 == 1) {
                v = (byte) (v + (1 << (8 - 3)) - (1 << (8 - 7)));
            }
            if (t2 == 1 && t4 == 0) {
                v = (byte) (v - (1 << (8 - 3)) + (1 << (8 - 7)));
            }
            buffer[i] = v;
        }

        return buffer;
    }

    private static byte[] movebit4(byte[] data) {
        byte[] buffer = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            buffer[i] = (byte) ~data[i];
        }
        return buffer;
    }

    private static byte[] bitmove_cycle(byte[] data) {
        int movebit = (SafeUtil.getIntRandom(6) + 1);
        byte[] buffer = new byte[data.length + 1];
        buffer[0] = (byte) movebit;
        for (int i = 0; i < data.length; i++) {
            byte v = data[i];
            buffer[i + 1] = (byte) ((v << movebit) | ((v & 0xff) >>> (8 - movebit)));
        }
        return buffer;
    }

    private static byte[] bitmove_cycle_reverse(byte[] data) {
        int movebit = data[0];
        byte[] buffer = new byte[data.length - 1];
        for (int i = 1; i < data.length; i++) {
            byte v = data[i];
            buffer[i - 1] = (byte) (((v & 0xff) >>> movebit) | (v << ((byte) (8 - movebit))));
        }
        return buffer;
    }

    private static byte[] bitmove(byte[] data) {
        int movebit = (SafeUtil.getIntRandom(6) + 1);
        byte[] buffer = new byte[data.length + 2];
        buffer[0] = (byte) movebit;
        byte suffix_bit = 0;
        int i = 0;
        for (; i < data.length; i++) {
            byte v = data[i];
            buffer[i + 1] = (byte) (suffix_bit | ((v & 0xff) >>> (8 - movebit)));
            suffix_bit = (byte) (v << movebit);
        }
        buffer[i+1] = suffix_bit;
        return buffer;
    }

    private static byte[] bitmove_reverse(byte[] data) {
        int movebit = data[0];
        byte[] buffer = new byte[data.length - 2];
        byte suffix_bit = (byte) (data[1] << (8 - movebit));
        for (int i = 0; i < data.length - 2; i++) {
            byte v = data[i+2];
            buffer[i] = (byte) ( suffix_bit | ((v & 0xff) >>> movebit));
            suffix_bit = (byte) (v << (8-movebit));
        }
        return buffer;
    }

    public static int getModelRandomIndex() {
        return SafeUtil.getIntRandom(17);
    }

    public static byte[] mixed_encrypt(byte[] data, int model) {
        byte[] buffer = null;
        switch (model) {
            case 0:
                buffer = switchmodel(data);
                break;
            case 1:
                buffer = matrix_t_refra(data);
                break;
            case 2:
                buffer = matrix_t_refra_re(data);
                break;
            case 3:
                buffer = matrix_t_row(data);
                break;
            case 4:
                buffer = matrix_t_col(data);
                break;
            case 5:
                buffer = matrix_f_refra(data);
                break;
            case 6:
                buffer = matrix_f_refra_re(data);
                break;
            case 7:
                buffer = matrix_f_row(data);
                break;
            case 8:
                buffer = matrix_f_col(data);
                break;
            case 9:
                buffer = xor(data);
                break;
            case 10:
                buffer = netfestival(data);
                break;
            case 11:
                buffer = movebit(data);
                break;
            case 12:
                buffer = movebit2(data);
                break;
            case 13:
                buffer = movebit3(data);
                break;
            case 14:
                buffer = movebit4(data);
                break;
            case 15:
                buffer = bitmove(data);
                break;
            case 16:
                buffer = bitmove_cycle(data);
                break;
            default:
                break;
        }
        return buffer;
    }

    public static byte[] mixed_decrypt(byte[] data, int model) {
        byte[] buffer = null;
        switch (model) {
            case 0:
                buffer = switchmodel(data);
                break;
            case 1:
                buffer = reverse_matrix_t_refra(data);
                break;
            case 2:
                buffer = reverse_matrix_t_refra_re(data);
                break;
            case 3:
                buffer = reverse_matrix_t_row(data);
                break;
            case 4:
                buffer = reverse_matrix_t_col(data);
                break;
            case 5:
                buffer = reverse_matrix_f_refra(data);
                break;
            case 6:
                buffer = reverse_matrix_f_refra_re(data);
                break;
            case 7:
                buffer = reverse_matrix_f_row(data);
                break;
            case 8:
                buffer = reverse_matrix_f_col(data);
                break;
            case 9:
                buffer = xor(data);
                break;
            case 10:
                buffer = netfestival(data);
                break;
            case 11:
                buffer = movebit(data);
                break;
            case 12:
                buffer = reverse_movebit2(data);
                break;
            case 13:
                buffer = movebit3(data);
                break;
            case 14:
                buffer = movebit4(data);
                break;
            case 15:
                buffer = bitmove_reverse(data);
                break;
            case 16:
                buffer = bitmove_cycle_reverse(data);
                break;
            default:
                break;
        }
        return buffer;
    }
}
