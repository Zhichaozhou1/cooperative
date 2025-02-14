#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <time.h>    // 用于高精度时间测量
#include <stdint.h>  // 用于 uint64_t

#define PRIME_BITS 512  // 大质数的位数
#define EXPONENT_T 1000 // t的值

// 辅助函数：计算两个timespec之间的差异，以纳秒为单位
uint64_t diff_in_ns(struct timespec start, struct timespec end) {
    uint64_t start_ns = start.tv_sec * 1000000000ULL + start.tv_nsec;
    uint64_t end_ns = end.tv_sec * 1000000000ULL + end.tv_nsec;
    return end_ns - start_ns;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("用法: %s <消息>\n", argv[0]);
        return 1;
    }

    const char *message = argv[1];
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // 定义timespec变量用于时间测量
    struct timespec total_start, total_end;
    struct timespec hash_start, hash_end;
    struct timespec p_start, p_end;
    struct timespec q_start, q_end;
    struct timespec mul_start, mul_end;
    struct timespec modexp_start, modexp_end;

    // 开始总时间计时
    clock_gettime(CLOCK_MONOTONIC, &total_start);

    // 计算SHA-256哈希
    clock_gettime(CLOCK_MONOTONIC, &hash_start);
    SHA256((unsigned char*)message, strlen(message), hash);
    clock_gettime(CLOCK_MONOTONIC, &hash_end);
    uint64_t hash_time = diff_in_ns(hash_start, hash_end);

    // 将哈希转换为十六进制字符串（可选，便于查看）
    printf("SHA-256 hash: ");
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]);
    printf("\n");

    // 初始化BIGNUM变量
    BIGNUM *bn_H = NULL;
    BIGNUM *bn_p = NULL;
    BIGNUM *bn_q = NULL;
    BIGNUM *bn_n = NULL;
    BIGNUM *bn_result = NULL;
    BN_CTX *ctx = NULL;

    // 创建新BIGNUM
    bn_H = BN_new();
    bn_p = BN_new();
    bn_q = BN_new();
    bn_n = BN_new();
    bn_result = BN_new();
    ctx = BN_CTX_new();

    if (!bn_H || !bn_p || !bn_q || !bn_n || !bn_result || !ctx) {
        fprintf(stderr, "内存分配失败\n");
        goto cleanup;
    }

    // 将哈希转换为BIGNUM
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, bn_H);

    // 生成大质数p
    clock_gettime(CLOCK_MONOTONIC, &p_start);
    printf("Generating large prime p...\n");
    if (!BN_generate_prime_ex(bn_p, PRIME_BITS, 1, NULL, NULL, NULL)) {
        fprintf(stderr, "生成质数p失败\n");
        goto cleanup;
    }
    clock_gettime(CLOCK_MONOTONIC, &p_end);
    uint64_t p_time = diff_in_ns(p_start, p_end);

    // 生成大质数q
    clock_gettime(CLOCK_MONOTONIC, &q_start);
    printf("Generating large prime q...\n");
    if (!BN_generate_prime_ex(bn_q, PRIME_BITS, 1, NULL, NULL, NULL)) {
        fprintf(stderr, "生成质数q失败\n");
        goto cleanup;
    }
    clock_gettime(CLOCK_MONOTONIC, &q_end);
    uint64_t q_time = diff_in_ns(q_start, q_end);

    // 计算n = p * q
    clock_gettime(CLOCK_MONOTONIC, &mul_start);
    if (!BN_mul(bn_n, bn_p, bn_q, ctx)) {
        fprintf(stderr, "计算n = p * q失败\n");
        goto cleanup;
    }
    clock_gettime(CLOCK_MONOTONIC, &mul_end);
    uint64_t mul_time = diff_in_ns(mul_start, mul_end);

    // 初始化result为H
    if (!BN_copy(bn_result, bn_H)) {
        fprintf(stderr, "复制H失败\n");
        goto cleanup;
    }

    // 开始模幂运算计时
    clock_gettime(CLOCK_MONOTONIC, &modexp_start);
    // 连续平方t次：H = H^(2^t) mod n
    printf("Start calculating H^(2^%d) mod n...\n", EXPONENT_T);
    for(int i = 0; i < EXPONENT_T; i++) {
        if (!BN_mod_sqr(bn_result, bn_result, bn_n, ctx)) {
            fprintf(stderr, "在平方步骤%d失败\n", i+1);
            goto cleanup;
        }

        if ((i+1) % 100 == 0) {
            printf("Finished %d squaremod\n", i+1);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &modexp_end);
    uint64_t modexp_time = diff_in_ns(modexp_start, modexp_end);

    // 打印结果
    char *result_str = BN_bn2hex(bn_result);
    if (result_str) {
        printf("H^(2^%d) mod n = %s\n", EXPONENT_T, result_str);
        OPENSSL_free(result_str);
    } else {
        fprintf(stderr, "转换结果失败\n");
    }

    // 结束总时间计时
    clock_gettime(CLOCK_MONOTONIC, &total_end);
    uint64_t total_time = diff_in_ns(total_start, total_end);

    // 打印各部分的执行时间
    printf("\nTime Calculation（ns）：\n");
    printf("1. SHA-256 Hash: %lu ns\n", hash_time);
    printf("2. Generating p: %lu ns\n", p_time);
    printf("3. Generating q: %lu ns\n", q_time);
    printf("4. Calculate n = p * q: %lu ns\n", mul_time);
    printf("5. H^(2^%d) mod n running time: %lu ns\n", EXPONENT_T, modexp_time);
    printf("6. Total time: %lu ns\n", total_time);

cleanup:
    // 释放资源
    if (bn_H) BN_free(bn_H);
    if (bn_p) BN_free(bn_p);
    if (bn_q) BN_free(bn_q);
    if (bn_n) BN_free(bn_n);
    if (bn_result) BN_free(bn_result);
    if (ctx) BN_CTX_free(ctx);

    return 0;
}
