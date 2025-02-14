#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <time.h>

#define PRIME_BITS 512
#define EXPONENT_T 1000

int main(int argc, char *argv[]) {

    const char *message = argv[1];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    struct timespec hash_start, hash_end;
    SHA256((unsigned char*)message, strlen(message), hash);

    // 将哈希转换为十六进制字符串（可选，便于查看）
    //printf("SHA-256哈希: ");
    //for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    //    printf("%02x", hash[i]);
    //printf("\n");

    // 初始化BIGNUM变量
    BIGNUM *bn_H = NULL;
    BIGNUM *bn_p = NULL;
    BIGNUM *bn_q = NULL;
    BIGNUM *bn_n = NULL;
    BIGNUM *bn_result = NULL;
    BIGNUM *bn_two = NULL;
    BN_CTX *ctx = NULL;

    // 创建新BIGNUM
    bn_H = BN_new();
    bn_p = BN_new();
    bn_q = BN_new();
    bn_n = BN_new();
    bn_result = BN_new();
    bn_two = BN_new();
    ctx = BN_CTX_new();

    if (!bn_H || !bn_p || !bn_q || !bn_n || !bn_result || !bn_two || !ctx) {
        fprintf(stderr, "内存分配失败\n");
        goto cleanup;
    }

    // 将哈希转换为BIGNUM
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, bn_H);

    // 生成大质数p和q
    //printf("生成大质数p...\n");
    if (!BN_generate_prime_ex(bn_p, PRIME_BITS, 1, NULL, NULL, NULL)) {
        fprintf(stderr, "生成质数p失败\n");
        goto cleanup;
    }

    //printf("生成大质数q...\n");
    if (!BN_generate_prime_ex(bn_q, PRIME_BITS, 1, NULL, NULL, NULL)) {
        fprintf(stderr, "生成质数q失败\n");
        goto cleanup;
    }

    // 计算n = p * q
    if (!BN_mul(bn_n, bn_p, bn_q, ctx)) {
        fprintf(stderr, "计算n = p * q失败\n");
        goto cleanup;
    }

    // 初始化result为H
    if (!BN_copy(bn_result, bn_H)) {
        fprintf(stderr, "复制H失败\n");
        goto cleanup;
    }

    // 初始化常数2
    if (!BN_set_word(bn_two, 2)) {
        fprintf(stderr, "设置常数2失败\n");
        goto cleanup;
    }
    clock_gettime(CLOCK_REALTIME, &hash_start);
    // 连续平方t次：H = H^(2^t) mod n
    //printf("开始计算 H^(2^%d) mod n...\n", EXPONENT_T);
    for(int i = 0; i < EXPONENT_T; i++) {
        if (!BN_mod_sqr(bn_result, bn_result, bn_n, ctx)) {
            fprintf(stderr, "在平方步骤%d失败\n", i+1);
            goto cleanup;
        }

        //if ((i+1) % 100 == 0) {
        //    printf("已完成 %d 次平方\n", i+1);
        //}
    }
    clock_gettime(CLOCK_REALTIME, &hash_end);
    // 打印结果
    char *result_str = BN_bn2hex(bn_result);
    if (result_str) {
        printf("H^(2^%d) mod n = %s\n", EXPONENT_T, result_str);
        OPENSSL_free(result_str);
    } else {
        fprintf(stderr, "转换结果失败\n");
    }
    double time_ms = (hash_end.tv_sec-hash_start.tv_sec)*1000 + (hash_end.tv_nsec-hash_start.tv_nsec)/1000000;
    printf("time: %f ms\n", time_ms);
cleanup:
    // 释放资源
    if (bn_H) BN_free(bn_H);
    if (bn_p) BN_free(bn_p);
    if (bn_q) BN_free(bn_q);
    if (bn_n) BN_free(bn_n);
    if (bn_result) BN_free(bn_result);
    if (bn_two) BN_free(bn_two);
    if (ctx) BN_CTX_free(ctx);

    return 0;
}
