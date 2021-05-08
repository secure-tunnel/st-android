//
// Created by rytong on 2021/4/27.
//

#include "security.h"
#include <android/log.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>

#define   LOG_TAG    "LOG_C"
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)


jbyteArray Java_com_st_security_SM3_hash(JNIEnv *env, jclass cls, jbyteArray data, jint datalen) {
    unsigned char * dataChars = (unsigned char *) (*env)->GetByteArrayElements(env, data, 0);

    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;
    unsigned char hash[64];
    unsigned int hash_len = 0;

    md = EVP_sm3();
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, dataChars, datalen);
    EVP_DigestFinal_ex(md_ctx, hash, &hash_len);
    EVP_MD_CTX_free(md_ctx);

    (*env)->ReleaseByteArrayElements(env, data, (jbyte*)dataChars, 0);

    jbyteArray resultArray = (*env)->NewByteArray(env, hash_len);
    (*env)->SetByteArrayRegion(env, resultArray, 0, hash_len, hash);

    if(md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }

    return resultArray;
}

jbyteArray Java_com_st_security_SM4_encrypt(JNIEnv *env, jclass cls, jbyteArray data, jint datalen, jbyteArray key, jint keylen, jbyteArray iv, jint ivlen) {
    /* 预处理参数类型 */
    unsigned char * keyChars = (unsigned char *) (*env)->GetByteArrayElements(env, key, 0);
    unsigned char * ivChars = (unsigned char *) (*env)->GetByteArrayElements(env, iv, 0);
    unsigned char * dataChars = (unsigned char *) (*env)->GetByteArrayElements(env, data, 0);
    EVP_CIPHER *evp_cipher = EVP_sm4_cbc();
    int cipher_key_length = EVP_CIPHER_key_length(evp_cipher);
    int cipher_iv_length = EVP_CIPHER_iv_length(evp_cipher);
    int i, cipher_length, final_length;
    unsigned char *ciphertext;

    if(cipher_key_length != keylen) {
        goto END;
    }
    if(cipher_iv_length != ivlen) {
        goto END;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL) {
        goto END;
    }

    EVP_EncryptInit_ex(ctx, evp_cipher, NULL, keyChars, ivChars);
    cipher_length = datalen + EVP_MAX_BLOCK_LENGTH;
    ciphertext = (unsigned char*)malloc(cipher_length);
    EVP_EncryptUpdate(ctx, ciphertext, &cipher_length, dataChars, datalen);
    EVP_EncryptFinal_ex(ctx, ciphertext + cipher_length, &final_length);

    jbyteArray resultArray = (*env)->NewByteArray(env, cipher_length + final_length);
    (*env)->SetByteArrayRegion(env, resultArray, 0, cipher_length + final_length, ciphertext);

    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);

    END:
    /* 释放资源 */
    (*env)->ReleaseByteArrayElements(env, data, (jbyte *) dataChars, 0);
    (*env)->ReleaseByteArrayElements(env, key, (jbyte *) keyChars, 0);
    (*env)->ReleaseByteArrayElements(env, iv, (jbyte *) ivChars, 0);

    return resultArray;
}

jbyteArray Java_com_st_security_SM4_decrypt(JNIEnv *env, jclass cls, jbyteArray data, jint datalen, jbyteArray key, jint keylen, jbyteArray iv, jint ivlen) {
    /* 预处理参数类型 */
    unsigned char * keyChars = (unsigned char *) (*env)->GetByteArrayElements(env, key, 0);
    unsigned char * ivChars = (unsigned char *) (*env)->GetByteArrayElements(env, iv, 0);
    unsigned char * dataChars = (unsigned char *) (*env)->GetByteArrayElements(env, data, 0);
    EVP_CIPHER *evp_cipher = EVP_sm4_cbc();
    int cipher_key_length = EVP_CIPHER_key_length(evp_cipher);
    int cipher_iv_length = EVP_CIPHER_iv_length(evp_cipher);
    int i, cipher_length, final_length;
    unsigned char *ciphertext;

    if(cipher_key_length != keylen) {
        goto END;
    }
    if(cipher_iv_length != ivlen) {
        goto END;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL) {
        goto END;
    }

    EVP_DecryptInit_ex(ctx, evp_cipher, NULL, keyChars, ivChars);
    cipher_length = datalen + EVP_MAX_BLOCK_LENGTH;
    ciphertext = (unsigned char*)malloc(cipher_length);
    EVP_DecryptUpdate(ctx, ciphertext, &cipher_length, dataChars, datalen);
    EVP_DecryptFinal_ex(ctx, ciphertext + cipher_length, &final_length);

    jbyteArray resultArray = (*env)->NewByteArray(env, cipher_length + final_length);
    (*env)->SetByteArrayRegion(env, resultArray, 0, cipher_length + final_length, ciphertext);

    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);

    END:
    /* 释放资源 */
    (*env)->ReleaseByteArrayElements(env, data, (jbyte *) dataChars, 0);
    (*env)->ReleaseByteArrayElements(env, key, (jbyte *) keyChars, 0);
    (*env)->ReleaseByteArrayElements(env, iv, (jbyte *) ivChars, 0);

    return resultArray;
}

int create_evp_pkey(unsigned char *key, int keyLen, int is_public, EVP_PKEY **out_pkey) {
    BIO *keybio = NULL;
    EC_KEY *ecKey = NULL;

    keybio = BIO_new_mem_buf(key, keyLen);

    if(keybio == NULL) {
        LOGI("BIO_new_mem_buf failed.\n");
        return 0;
    }
    if(is_public){
        ecKey = PEM_read_bio_EC_PUBKEY(keybio, &ecKey, NULL, NULL);
        if(ecKey == NULL) {
            LOGI("PEM_read_bio_EC_PUBKEY failed\n");
            BIO_free(keybio);
            return 0;
        }
    }else{
        ecKey = PEM_read_bio_ECPrivateKey(keybio, &ecKey, NULL, NULL);
        if(ecKey == NULL) {
            LOGI("PEM_read_bio_ECPrivateKey failed\n");
            BIO_free(keybio);
            return 0;
        }
    }
    int ret = EVP_PKEY_set1_EC_KEY(*out_pkey, ecKey);
    if(ret != 1){
        LOGI("EVP_PKEY_set1_EC_KEY failed. ", ret);
        EC_KEY_free(ecKey);
        BIO_free(keybio);
        return 0;
    }

    if(*out_pkey == NULL) {
        LOGI("Failed to Get Key\n");
        EC_KEY_free(ecKey);
        BIO_free(keybio);
        return 0;
    }
    EC_KEY_free(ecKey);
    BIO_free(keybio);
    return 1;
}

jbyteArray Java_com_st_security_SM2_encrypt(JNIEnv *env, jclass cls, jbyteArray data, jint datalen, jbyteArray publickey, jint publickeylen) {
    EVP_PKEY_CTX *ectx = NULL;
    EVP_PKEY *pkey = EVP_PKEY_new();
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len;
    jbyteArray resultArray = NULL;

    unsigned char * dataChars = (unsigned char *) (*env)->GetByteArrayElements(env, data, 0);
    unsigned char * pubKeyChars = (unsigned char *) (*env)->GetByteArrayElements(env, publickey, 0);

    if(create_evp_pkey(pubKeyChars, publickeylen, 1, &pkey) == 0) {
        LOGI("create_evp_pkey failed\n");
        goto clean_up;
    }
    /* compute SM2 encryption */
    if((EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) != 1) {
        LOGI("EVP_PKEY_set_alias_type failed.\n");
        goto clean_up;
    }
    if(!(ectx = EVP_PKEY_CTX_new(pkey, NULL))){
        LOGI("EVP_PKEY_CTX_new failed.\n");
        goto clean_up;
    }
    if((EVP_PKEY_encrypt_init(ectx)) != 1) {
        LOGI("EVP_PKEY_encrypt_init failed.\n");
        goto clean_up;
    }
    if((EVP_PKEY_encrypt(ectx, NULL, &ciphertext_len, dataChars, datalen)) != 1){
        LOGI("EVP_PKEY_encrypt failed.\n");
        goto clean_up;
    }
    if(!(ciphertext = (unsigned char*)malloc(ciphertext_len))){
        LOGI("malloc failed.\n");
        goto clean_up;
    }
    if((EVP_PKEY_encrypt(ectx, ciphertext, &ciphertext_len, dataChars, datalen)) != 1){
        LOGI("EVP_PKEY_encrypt failed.\n");
        goto clean_up;
    }

    resultArray = (*env)->NewByteArray(env, ciphertext_len);
    (*env)->SetByteArrayRegion(env, resultArray, 0, ciphertext_len, ciphertext);

    clean_up:
    if(pkey){
        EVP_PKEY_free(pkey);
    }
    if(ectx){
        EVP_PKEY_CTX_free(ectx);
    }
    if(ciphertext){
        free(ciphertext);
    }
    (*env)->ReleaseByteArrayElements(env, data, (jbyte *) dataChars, 0);
    (*env)->ReleaseByteArrayElements(env, publickey, (jbyte *) pubKeyChars, 0);

    return resultArray;
}

jbyteArray Java_com_st_security_SM2_decrypt(JNIEnv *env, jclass cls, jbyteArray data, jint datalen, jbyteArray privatekey, jint privatekeylen) {
    EVP_PKEY_CTX *ectx = NULL;
    EVP_PKEY *pkey = EVP_PKEY_new();
    unsigned char *plaintext = NULL;
    size_t plaintext_len;
    jbyteArray resultArray = NULL;

    unsigned char * dataChars = (unsigned char *) (*env)->GetByteArrayElements(env, data, 0);
    unsigned char * privKeyChars = (unsigned char *) (*env)->GetByteArrayElements(env, privatekey, 0);

    if(create_evp_pkey(privKeyChars, privatekeylen, 0, &pkey) == 0) {
        LOGI("create_evp_pkey failed.\n");
        goto clean_up;
    }
    if((EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) != 1) {
        LOGI("EVP_PKEY_set_alias_type failed.\n");
        goto clean_up;
    }
    if(!(ectx = EVP_PKEY_CTX_new(pkey, NULL))) {
        LOGI("EVP_PKEY_CTX_new failed.\n");
        goto clean_up;
    }
    /* compute SM2 decryption */
    if((EVP_PKEY_decrypt_init(ectx)) != 1){
        LOGI("EVP_PKEY_decrypt_init failed.\n");
        goto clean_up;
    }
    if((EVP_PKEY_decrypt(ectx, NULL, &plaintext_len, dataChars, datalen)) != 1){
        LOGI("EVP_PKEY_decrypt failed.\n");
        goto clean_up;
    }
    if(!(plaintext = (unsigned char*)malloc(plaintext_len))){
        LOGI("malloc failed.\n");
        goto clean_up;
    }
    if((EVP_PKEY_decrypt(ectx, plaintext, &plaintext_len, dataChars, datalen)) != 1){
        LOGI("EVP_PKEY_decrypt failed.\n");
        goto clean_up;
    }

    resultArray = (*env)->NewByteArray(env, plaintext_len);
    (*env)->SetByteArrayRegion(env, resultArray, 0, plaintext_len, plaintext);

    clean_up:
    if(pkey){
        EVP_PKEY_free(pkey);
    }
    if(ectx){
        EVP_PKEY_CTX_free(ectx);
    }
    if(plaintext){
        free(plaintext);
    }
    (*env)->ReleaseByteArrayElements(env, data, (jbyte *) dataChars, 0);
    (*env)->ReleaseByteArrayElements(env, privatekey, (jbyte *) privKeyChars, 0);

    return resultArray;
}

jbyteArray Java_com_st_security_SM2_sign(JNIEnv *env, jclass cls, jbyteArray data, jint datalen, jbyteArray privatekey, jint privatekeylen) {
    EVP_PKEY *evpPkey = EVP_PKEY_new();
    EVP_MD_CTX *evpMdCtx = NULL;
    int len_sig = 0;
    jbyteArray resultArray = NULL;
    unsigned char szSign[256] = {0};

    unsigned char * dataChars = (unsigned char *) (*env)->GetByteArrayElements(env, data, 0);
    unsigned char * privKeyChars = (unsigned char *) (*env)->GetByteArrayElements(env, privatekey, 0);

    if(create_evp_pkey(privKeyChars, privatekeylen, 0, &evpPkey) == 0){
        LOGI("create_evp_pkey failed\n");
        goto END;
    }
    if((EVP_PKEY_set_alias_type(evpPkey, EVP_PKEY_SM2)) != 1) {
        LOGI("EVP_PKEY_set_alias_type failed.\n");
        goto END;
    }
    /* do signature */
    evpMdCtx = EVP_MD_CTX_new();
    if(evpMdCtx == NULL) {
        LOGI("EVP_MD_CTX_new failed");
        goto END;
    }
    EVP_MD_CTX_init(evpMdCtx);
    if(EVP_SignInit_ex(evpMdCtx, EVP_sm3(), NULL) != 1) {
        LOGI("EVP_SignInit_ex failed");
        goto END;
    }
    if(EVP_SignUpdate(evpMdCtx, dataChars, datalen) != 1) {
        LOGI("EVP_SignUpdate failed");
        goto END;
    }
    if(EVP_SignFinal(evpMdCtx, szSign, &len_sig, evpPkey) != 1){
        LOGI("EVP_SignFinal failed");
        goto END;
    }

    resultArray = (*env)->NewByteArray(env, len_sig);
    (*env)->SetByteArrayRegion(env, resultArray, 0, len_sig, szSign);

    END:
    /* 释放资源 */
    if(evpMdCtx != NULL){
        EVP_MD_CTX_free(evpMdCtx);
    }
    if(evpPkey != NULL){
        EVP_PKEY_free(evpPkey);
    }
    (*env)->ReleaseByteArrayElements(env, data, (jbyte *) dataChars, 0);
    (*env)->ReleaseByteArrayElements(env, privatekey, (jbyte *) privKeyChars, 0);

    return resultArray;
}

jint Java_com_st_security_SM2_verify(JNIEnv *env, jclass cls, jbyteArray data, jint datalen, jbyteArray signdata, jint signdatalen, jbyteArray publickey, jint publickeylen) {
    int ret_val = 0;
    EVP_PKEY *evpPkey = EVP_PKEY_new();
    EVP_MD_CTX *evpMdCtx = NULL;

    unsigned char *dataChars = (unsigned char *) (*env)->GetByteArrayElements(env, data, 0);
    unsigned char *pubKeyChars = (unsigned char *) (*env)->GetByteArrayElements(env, publickey, 0);
    unsigned char *signdataChars = (unsigned char*)(*env)->GetByteArrayElements(env, signdata, 0);

    if(create_evp_pkey(pubKeyChars, publickeylen, 1, &evpPkey) == 0){
        LOGI("create_evp_pkey failed");
        ret_val = -1;
        goto END;
    }
    if((EVP_PKEY_set_alias_type(evpPkey, EVP_PKEY_SM2)) != 1) {
        LOGI("EVP_PKEY_set_alias_type failed.\n");
        goto END;
    }
    /* do signature */
    evpMdCtx = EVP_MD_CTX_new();
    if(evpMdCtx == NULL) {
        LOGI("EVP_MD_CTX_new failed");
        ret_val = -2;
        goto END;
    }
    EVP_MD_CTX_init(evpMdCtx);
    if(EVP_VerifyInit_ex(evpMdCtx, EVP_sm3(), NULL) != 1) {
        LOGI("EVP_SignInit_ex failed");
        ret_val = -3;
        goto END;
    }
    if(EVP_VerifyUpdate(evpMdCtx, dataChars, datalen) != 1) {
        LOGI("EVP_SignUpdate failed");
        ret_val = -4;
        goto END;
    }
    if(EVP_VerifyFinal(evpMdCtx, signdataChars, signdatalen, evpPkey) != 1){
        LOGI("EVP_SignFinal failed");
        ret_val = -5;
        goto END;
    }
    ret_val = 0;
    END:
    /* 释放资源 */
    if(evpMdCtx != NULL){
        EVP_MD_CTX_free(evpMdCtx);
    }
    if(evpPkey != NULL){
        EVP_PKEY_free(evpPkey);
    }
    (*env)->ReleaseByteArrayElements(env, data, (jbyte *) dataChars, 0);
    (*env)->ReleaseByteArrayElements(env, publickey, (jbyte *) pubKeyChars, 0);
    (*env)->ReleaseByteArrayElements(env, signdata, (jbyte*)signdataChars, 0);

    return (jint)ret_val;
}
