/*
 * HMAC-SHA-224/256/384/512 implementation
 * Last update: 06/15/2005
 * Issue date:  06/15/2005
 *
 * Copyright (C) 2005 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Copyright (C) 2013 Andi Palo <sanandrea8080@gmail.com>
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "hmac_sha256.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef ANDROID_BUILD
#include <jni.h>
#include <android/log.h>

#define LOG_TAG "AJNI"
#define LOG(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif


static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static int encoding_table_size = 64;
static int mod_table[] = {0, 2, 1};

/* HMAC-SHA-256 functions */

void hmac_sha256_init(hmac_sha256_ctx *ctx, const unsigned char *key,
                      unsigned int key_size)
{
    unsigned int fill;
    unsigned int num;

    const unsigned char *key_used;
    unsigned char key_temp[SHA256_DIGEST_SIZE];
    int i;

    if (key_size == SHA256_BLOCK_SIZE) {
        key_used = key;
        num = SHA256_BLOCK_SIZE;
    } else {
        if (key_size > SHA256_BLOCK_SIZE){
            num = SHA256_DIGEST_SIZE;
            sha256(key, key_size, key_temp);
            key_used = key_temp;
        } else { /* key_size > SHA256_BLOCK_SIZE */
            key_used = key;
            num = key_size;
        }
        fill = SHA256_BLOCK_SIZE - num;

        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

    sha256_init(&ctx->ctx_inside);
    sha256_update(&ctx->ctx_inside, ctx->block_ipad, SHA256_BLOCK_SIZE);

    sha256_init(&ctx->ctx_outside);
    sha256_update(&ctx->ctx_outside, ctx->block_opad,
                  SHA256_BLOCK_SIZE);

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
           sizeof(sha256_ctx));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
           sizeof(sha256_ctx));
}

void hmac_sha256_reinit(hmac_sha256_ctx *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(sha256_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(sha256_ctx));
}

void hmac_sha256_update(hmac_sha256_ctx *ctx, const unsigned char *message,
                        unsigned int message_len)
{
    sha256_update(&ctx->ctx_inside, message, message_len);
}

void hmac_sha256_final(hmac_sha256_ctx *ctx, unsigned char *mac,
                       unsigned int mac_size)
{
    unsigned char digest_inside[SHA256_DIGEST_SIZE];
    unsigned char mac_temp[SHA256_DIGEST_SIZE];

    sha256_final(&ctx->ctx_inside, digest_inside);
    sha256_update(&ctx->ctx_outside, digest_inside, SHA256_DIGEST_SIZE);
    sha256_final(&ctx->ctx_outside, mac_temp);
    memcpy(mac, mac_temp, mac_size);
}

void hmac_sha256(const unsigned char *key, unsigned int key_size,
          const unsigned char *message, unsigned int message_len,
          unsigned char *mac, unsigned mac_size)
{
    hmac_sha256_ctx ctx;

    hmac_sha256_init(&ctx, key, key_size);
    hmac_sha256_update(&ctx, message, message_len);
    hmac_sha256_final(&ctx, mac, mac_size);
}

char *a(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {
	int i,j;
    *output_length = 4 * ((input_length + 2) / 3);
    //LOGE("output size is %d", *output_length);
    char *encoded_data = malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}
char *b(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {
	int i,j;
    *output_length = 4 * ((input_length + 2) / 3);
    //LOGE("output size is %d", *output_length);
    char *encoded_data = malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}
char* c(const char *message, unsigned int m_size,
		unsigned char* key, unsigned int k_size,int* output_size){
	unsigned int mac_256_size = SHA256_DIGEST_SIZE;
	unsigned char mac[mac_256_size];
	char * encode;
	size_t enc_size;

	hmac_sha256(key, k_size, (unsigned char *) message,
	                    m_size, mac, mac_256_size);

	encode = a(mac,mac_256_size, &enc_size);

	*output_size = enc_size;
	encode[enc_size] = '\0';
	//LOG("in encode %s",encode);
	return encode;
}

unsigned char* d(int* size){
	unsigned char * encode;
	int i;
	const char* aux1 = "wW:zzzzz:";
	const char* aux2 = "'^-->";
	const char* aux3 = ".;*+";
    
	int salt = 101;
	int pepper = 2;
	int rain = 3;
	int snow = 5;
    
    int random_str1_length = 11;
    int random_str2_length = 21;
    
    int output_size = random_str1_length + random_str2_length + strlen(aux1) + strlen(aux2) + strlen(aux3) + 1;
	encode = malloc(output_size);
    
	int counter = 0;

	for (i = 0; i < random_str1_length; i++){
		encode[i] = encoding_table[(i * rain + salt) % encoding_table_size];
		counter++;
	}
	for (i = 0; i < strlen(aux1); i++){
		encode[counter] = aux1[i];
		counter++;
	}
	for (i = 0; i < strlen(aux2); i++){
		encode[counter] = aux2[i];
		counter++;
	}
	for (i = 0; i < strlen(aux3); i++){
		encode[counter] = aux3[i];
		counter++;
	}
	for (i = 0; i < random_str2_length; i++){
		encode[counter] = encoding_table[(i * snow + pepper) % encoding_table_size];
		counter++;
	}

	encode[output_size - 1] = '\0';
	*size = output_size - 1;
	return encode;
}

char* hmac_sha1_init(hmac_sha256_ctx* ctx,unsigned char * message, unsigned int l){
	return NULL;
}
char* hmac_sha1_reinit(hmac_sha256_ctx* ctx){
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
           sizeof(sha256_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
           sizeof(sha256_ctx));
    return NULL;
}

char* g(const char* _msg,int _size, int* error, int* output_length){
    unsigned char *ball = NULL;
    int earth;
    char *luna;
	int result;
    
    int mars = _size;
    const char *venus = _msg;
    
    if (!venus ) {
        return NULL;
    }
    
	ball = d(&earth);
    luna = c(venus, mars, ball, earth, &result);
#ifdef SHOW_PASS
    printf("Pass generated is %s \n",ball);
    printf("Encryption is: %s %d\n",luna, result);
#endif
    *output_length = result;
    free(ball);
    return luna;
}

#ifdef ANDROID_BUILD
jstring
Java_com_your_extended_class_name_including_package(
		JNIEnv* env, jobject obj, jstring message) {
    unsigned char *ball;
    unsigned int earth;
    char *luna;
	int result;

	// Le JNI 
	int mars = (*env)->GetStringLength(env, message);
    const char *venus = (*env)->GetStringUTFChars(env, message, 0);

    if (!venus ) {
            LOGE("ERROR : message Conversion error in native");
            (*env)->ReleaseStringUTFChars(env, message, venus);
            return NULL;
    }

    //strcpy((char *) ball, "password");

	ball = d(&earth);

    luna = c(venus, mars, ball, earth, &result);
#ifdef SHOW_PASS
    LOGE("Pass generated is %s",ball);
#endif
    (*env)->ReleaseStringUTFChars(env,message,venus);
    free(ball);
    return (*env)->NewStringUTF(env, luna);
}
#endif