//
// Created by rytong on 2021/4/27.
//
#include <jni.h>

#ifndef BMF_SECURITY_H
#define BMF_SECURITY_H

#ifdef __cplusplus
extern "C" {
#endif

    JNIEXPORT jbyteArray JNICALL Java_com_bankcomm_bmf_security_SM3_hash(JNIEnv *env, jclass, jbyteArray, jint);
    JNIEXPORT jbyteArray JNICALL Java_com_bankcomm_bmf_security_SM4_encrypt(JNIEnv*, jclass, jbyteArray, jint, jbyteArray, jint, jbyteArray, jint);
    JNIEXPORT jbyteArray JNICALL Java_com_bankcomm_bmf_security_SM4_decrypt(JNIEnv*, jclass, jbyteArray, jint, jbyteArray, jint, jbyteArray, jint);
    JNIEXPORT jbyteArray JNICALL  Java_com_bankcomm_bmf_security_SM2_encrypt(JNIEnv*, jclass, jbyteArray, jint, jbyteArray, jint);
    JNIEXPORT jbyteArray JNICALL  Java_com_bankcomm_bmf_security_SM2_decrypt(JNIEnv*, jclass, jbyteArray, jint, jbyteArray, jint);
    JNIEXPORT jbyteArray JNICALL  Java_com_bankcomm_bmf_security_SM2_sign(JNIEnv*, jclass, jbyteArray, jint, jbyteArray, jint);
    JNIEXPORT jint JNICALL  Java_com_bankcomm_bmf_security_SM2_verify(JNIEnv*, jclass, jbyteArray, jint, jbyteArray, jint, jbyteArray, jint);

#ifdef __cplusplus
}
#endif

#endif //BMF_SECURITY_H
