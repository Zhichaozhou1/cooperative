/*#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>*/
#include "lab.h"
/*EC_GROUP *ec_group;
BIGNUM *master_secret;
EC_POINT *public_key;
BIGNUM *private_key;
EC_POINT *P;
BIGNUM *order;
BIGNUM *x;
EC_POINT *Ppub;*/

EC_KEY *read_private_key(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("无法打开私钥文件：%s\n", filename);
        return NULL;
    }

    EC_KEY *ec_key = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (ec_key == NULL) {
        printf("读取私钥失败。\n");
        ERR_print_errors_fp(stderr);
    }

    return ec_key;
}

EC_KEY *read_public_key(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("无法打开公钥文件：%s\n", filename);
        return NULL;
    }

    EC_KEY *ec_key = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (ec_key == NULL) {
        printf("读取公钥失败。\n");
        ERR_print_errors_fp(stderr);
    }

    return ec_key;
}

void setup() {
    // 创建椭圆曲线组，使用指定的曲线
    ec_group = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1);
    if (ec_group == NULL) {
        printf("创建椭圆曲线组失败。\n");
        exit(1);
    }

    // 获取椭圆曲线的阶 q
    order = BN_new();
    EC_GROUP_get_order(ec_group, order, NULL);

    // 初始化基点 P
    P = EC_POINT_new(ec_group);
    EC_POINT_copy(P, EC_GROUP_get0_generator(ec_group));

    // 从 .pem 文件中读取系统私钥
    EC_KEY *private_ec_key = read_private_key("private_key.pem");
    if (private_ec_key == NULL) {
        printf("读取私钥失败。\n");
        exit(1);
    }

    // 获取私钥的 BIGNUM 表示
    const BIGNUM *priv_key_bn = EC_KEY_get0_private_key(private_ec_key);
    if (priv_key_bn == NULL) {
        printf("无法获取私钥的 BIGNUM 表示。\n");
        exit(1);
    }
    x = BN_dup(priv_key_bn);

    // 从 .pem 文件中读取系统公钥
    EC_KEY *public_ec_key = read_public_key("public_key.pem");
    if (public_ec_key == NULL) {
        printf("读取公钥失败。\n");
        exit(1);
    }

    const EC_POINT *pub_key_point = EC_KEY_get0_public_key(public_ec_key);
    if (pub_key_point == NULL) {
        printf("无法获取公钥的 EC_POINT 表示。\n");
        exit(1);
    }
    Ppub = EC_POINT_dup(pub_key_point, ec_group);

    EC_KEY_free(private_ec_key);
    EC_KEY_free(public_ec_key);
}

int BN_bn_xor(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) {
    int len_a = BN_num_bytes(a);
    int len_b = BN_num_bytes(b);
    int len = (len_a > len_b) ? len_a : len_b;

    unsigned char *buf_a = (unsigned char *)calloc(len, sizeof(unsigned char));
    unsigned char *buf_b = (unsigned char *)calloc(len, sizeof(unsigned char));
    unsigned char *buf_r = (unsigned char *)calloc(len, sizeof(unsigned char));

    if (!buf_a || !buf_b || !buf_r) {
        printf("内存分配失败。\n");
        return 0;
    }

    BN_bn2binpad(a, buf_a + (len - len_a), len_a);
    BN_bn2binpad(b, buf_b + (len - len_b), len_b);

    for (int i = 0; i < len; i++) {
        buf_r[i] = buf_a[i] ^ buf_b[i];
    }

    BN_bin2bn(buf_r, len, r);

    free(buf_a);
    free(buf_b);
    free(buf_r);

    return 1;
}

void hash_string_to_scalar(const char *str, BIGNUM *scalar) {
    unsigned char hash_output[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)str, strlen(str), hash_output);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *scalar_temp = BN_new();
    BN_bin2bn(hash_output, MD5_DIGEST_LENGTH, scalar_temp);
    char *hex_str_order = BN_bn2hex(order);
    char *hex_str_scalar = BN_bn2hex(scalar);
    BN_mod(scalar, scalar_temp, order, ctx);
}

void hash_point_to_MD5(const EC_POINT *point, unsigned char *hash_output) {
    unsigned char *buf;
    size_t buf_len = EC_POINT_point2buf(ec_group, point, POINT_CONVERSION_COMPRESSED, &buf, NULL);

    MD5(buf, buf_len, hash_output);

    OPENSSL_free(buf);
}

void generate_pseudonym(const char *RID, EC_POINT **AID1, BIGNUM **AID2_bn, BIGNUM **wi_bn, BIGNUM **alpha_i, EC_POINT **alpha_i_point) {
    BIGNUM *wi = BN_new();
    BN_rand_range(wi, order);
    *AID1 = EC_POINT_new(ec_group);
    *alpha_i_point = EC_POINT_new(ec_group);
    EC_POINT_mul(ec_group, *AID1, NULL, P, wi, NULL);
    *alpha_i = BN_new();
    hash_string_to_scalar(RID, *alpha_i);
    EC_POINT_mul(ec_group, *alpha_i_point, NULL, Ppub, *alpha_i, NULL);
    EC_POINT *wi_Ppub = EC_POINT_new(ec_group);
    EC_POINT_mul(ec_group, wi_Ppub, NULL, Ppub, wi, NULL);
    unsigned char hash_output[MD5_DIGEST_LENGTH];
    hash_point_to_MD5(wi_Ppub, hash_output);
    BIGNUM *hash_bn = BN_new();
    BN_bin2bn(hash_output, MD5_DIGEST_LENGTH, hash_bn);
    BIGNUM *RID_bn = BN_new();
    BN_bin2bn((unsigned char *)RID, strlen(RID), RID_bn);
    *AID2_bn = BN_new();
    BN_bn_xor(*AID2_bn, RID_bn, hash_bn);
    *wi_bn = BN_dup(wi);
    BN_free(wi);
    EC_POINT_free(wi_Ppub);
    BN_free(hash_bn);
    BN_free(RID_bn);
}

void compute_user_private_key(BIGNUM *wi, BIGNUM *alpha_i, BIGNUM **ski_bn) {
    BIGNUM *alpha_x = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_mul(alpha_x, alpha_i, x, order, ctx);

    *ski_bn = BN_new();
    BN_mod_add(*ski_bn, wi, alpha_x, order, ctx);

    BN_free(alpha_x);
}

EC_POINT *hash_to_point(const char *str) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)str, strlen(str), hash);

    BIGNUM *x = BN_new();
    BN_bin2bn(hash, MD5_DIGEST_LENGTH, x);

    EC_POINT *point = EC_POINT_new(ec_group);
    while (1) {
        if (EC_POINT_set_compressed_coordinates_GFp(ec_group, point, x, 0, NULL)) {
            if (EC_POINT_is_on_curve(ec_group, point, NULL)) {
                break;
            }
        }
        BN_add(x, x, BN_value_one());
    }

    BN_free(x);
    return point;
}


void compute_beta_i(const EC_POINT *AID1, const BIGNUM *AID2_bn, const char *Ti_str, const BIGNUM *Ri_bn, const unsigned char *Mi, int Mi_len, BIGNUM *beta_i) {
    BN_CTX *ctx = BN_CTX_new();
    unsigned char *AID1_buf = NULL;
    size_t AID1_len = EC_POINT_point2buf(ec_group, AID1, POINT_CONVERSION_COMPRESSED, &AID1_buf, NULL);

    int AID2_len = BN_num_bytes(AID2_bn);
    unsigned char *AID2_buf = (unsigned char *)OPENSSL_malloc(AID2_len);
    BN_bn2bin(AID2_bn, AID2_buf);

    int Ri_len = BN_num_bytes(Ri_bn);
    unsigned char *Ri_buf = (unsigned char *)OPENSSL_malloc(Ri_len);
    BN_bn2bin(Ri_bn, Ri_buf);

    size_t data_len = AID1_len + AID2_len + strlen(Ti_str) + Ri_len + Mi_len;

    unsigned char *data = (unsigned char *)OPENSSL_malloc(data_len);
    unsigned char *ptr = data;

    memcpy(ptr, AID1_buf, AID1_len);
    ptr += AID1_len;

    memcpy(ptr, AID2_buf, AID2_len);
    ptr += AID2_len;

    memcpy(ptr, Ti_str, strlen(Ti_str));
    ptr += strlen(Ti_str);

    memcpy(ptr, Ri_buf, Ri_len);
    ptr += Ri_len;

    memcpy(ptr, Mi, Mi_len);

    unsigned char hash_output[MD5_DIGEST_LENGTH];
    MD5(data, data_len, hash_output);

    BN_bin2bn(hash_output, MD5_DIGEST_LENGTH, beta_i);
    BN_mod(beta_i, beta_i, order, ctx);

    OPENSSL_free(AID1_buf);
    OPENSSL_free(AID2_buf);
    OPENSSL_free(Ri_buf);
    OPENSSL_free(data);
}

void keygen(const char *user_id, const char *timestamp) {
    char id_ts[256];
    snprintf(id_ts, sizeof(id_ts), "%s%s", user_id, timestamp);
    EC_POINT *Q_id = hash_to_point(id_ts);

    private_key = BN_new();
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(ec_group, order, NULL);

    BN_rand(private_key, 256, -1, 0);

    public_key = EC_POINT_new(ec_group);
    EC_POINT_mul(ec_group, public_key, private_key, NULL, NULL, NULL);

    EC_POINT_free(Q_id);
    BN_free(order);
}

void user_sign_message(BIGNUM *ski_bn, const EC_POINT *AID1, const BIGNUM *AID2_bn, const char *Ti_str, const unsigned char *Mi, int Mi_len, BIGNUM **sigma_i_bn, BIGNUM **Ri_bn, EC_POINT *sigma_P) {
    BIGNUM *Ri = BN_new();
    BIGNUM *bn = BN_new();
    struct timespec time_start;
    struct timespec time_end;
    BN_CTX *ctx = BN_CTX_new();
    BN_rand_range(Ri, order);
    BIGNUM *beta_i = BN_new();
    //clock_gettime(CLOCK_REALTIME, &time_start);
    compute_beta_i(AID1, AID2_bn, Ti_str, Ri, Mi, Mi_len, beta_i);
    //clock_gettime(CLOCK_REALTIME, &time_end);
    *sigma_i_bn = BN_new();
    BIGNUM *beta_Ri = BN_new();
    BN_mod_mul(beta_Ri, beta_i, Ri, order, ctx);
    BN_mod_add(*sigma_i_bn, ski_bn, beta_Ri, order, ctx);
    //clock_gettime(CLOCK_REALTIME, &time_end);
    //sigma_P = EC_POINT_new(ec_group);
    //EC_POINT_mul(ec_group, sigma_P, NULL, P, *sigma_i_bn, NULL);
    //EC_KEY_precompute_mult(ec_key, ctx);
    clock_gettime(CLOCK_REALTIME, &time_start);
    //BN_hex2bn(&bn, "1BC16D674EC80000");
    EC_POINT_mul(ec_group, sigma_P, NULL, P, *sigma_i_bn, ctx);
    //EC_POINT_mul(ec_group, sigma_P, NULL, P, bn, ctx);
    clock_gettime(CLOCK_REALTIME, &time_end);
    *Ri_bn = BN_dup(Ri);
    double latency=(time_end.tv_sec-time_start.tv_sec)*1000.0+(time_end.tv_nsec-time_start.tv_nsec)/1000000.0;
    printf("latency send:%f\n",latency);
    BN_free(Ri);
    BN_free(beta_i);
    BN_free(beta_Ri);
}

int verify_signature(const EC_POINT *AID1, const BIGNUM *AID2_bn, const  EC_POINT *alpha_i_point, const char *Ti_str, const unsigned char *Mi, int Mi_len, EC_POINT *sigma_P, BIGNUM *Ri_bn) {
        struct timespec time_start;
        struct timespec time_end;
    BN_CTX *ctx = BN_CTX_new();
    //EC_POINT *alpha_Ppub = EC_POINT_new(ec_group);
//      clock_gettime(CLOCK_REALTIME, &time_start);
    //EC_POINT_mul(ec_group, alpha_Ppub, NULL, Ppub, alpha_i, NULL);
        //clock_gettime(CLOCK_REALTIME, &time_end);
        //double latency=(time_end.tv_sec-time_start.tv_sec)*1000.0+(time_end.tv_nsec-time_start.tv_nsec)/1000000.0;
        //printf("decode latency:%f\n",latency);
    EC_POINT *Pi = EC_POINT_new(ec_group);
    EC_POINT_add(ec_group, Pi, AID1, alpha_i_point, NULL);
    BIGNUM *beta_i = BN_new();
    compute_beta_i(AID1, AID2_bn, Ti_str, Ri_bn, Mi, Mi_len, beta_i);
        //clock_gettime(CLOCK_REALTIME, &time_start);
    //EC_POINT *sigma_P = EC_POINT_new(ec_group);
    //EC_POINT_mul(ec_group, sigma_P, NULL, P, sigma_i_bn, NULL);
        //clock_gettime(CLOCK_REALTIME, &time_end);
        //double latency1=(time_end.tv_sec-time_start.tv_sec)*1000.0+(time_end.tv_nsec-time_start.tv_nsec)/1000000.0;
        //printf("decode latency1:%f\n",latency1);
    BIGNUM *beta_Ri = BN_new();
    BN_mod_mul(beta_Ri, beta_i, Ri_bn, order, ctx);
    EC_POINT *beta_Ri_P = EC_POINT_new(ec_group);
    clock_gettime(CLOCK_REALTIME, &time_start);
    EC_POINT_mul(ec_group, beta_Ri_P, NULL, P, beta_Ri, ctx);
    clock_gettime(CLOCK_REALTIME, &time_end);
    EC_POINT *S = EC_POINT_new(ec_group);
    EC_POINT_add(ec_group, S, Pi, beta_Ri_P, NULL);
    int ret = EC_POINT_cmp(ec_group, sigma_P, S, NULL) == 0;
//      clock_gettime(CLOCK_REALTIME, &time_end);
        double latency2=(time_end.tv_sec-time_start.tv_sec)*1000.0+(time_end.tv_nsec-time_start.tv_nsec)/1000000.0;
        printf("latency receive:%f\n",latency2);
    //EC_POINT_free(alpha_Ppub);
    EC_POINT_free(Pi);
    BN_free(beta_i);
    EC_POINT_free(sigma_P);
    BN_free(beta_Ri);
    EC_POINT_free(beta_Ri_P);
    EC_POINT_free(S);

    return ret;
}

/*int main() {
    //OpenSSL_add_all_algorithms();
    setup();
    printf("setup success!\n");
    const char *RID = "user@example.com";

    EC_POINT *AID1;
    BIGNUM *AID2_bn;
    BIGNUM *wi_bn;
    BIGNUM *alpha_i;
    generate_pseudonym(RID, &AID1, &AID2_bn, &wi_bn, &alpha_i);
    printf("pseudonym generation success!\n");
    BIGNUM *ski_bn;
    compute_user_private_key(wi_bn, alpha_i, &ski_bn);
    printf("prikey generation success!\n");
    char Ti_str[20];
    time_t now = time(NULL);
    snprintf(Ti_str, sizeof(Ti_str), "%ld", now);

    const unsigned char *message = (unsigned char *)"Hello, VANET with updated beta_i!";
    int msg_len = strlen((char *)message);

    BIGNUM *sigma_i_bn;
    BIGNUM *Ri_bn;
    printf("prepare success!\n");
    user_sign_message(ski_bn, AID1, AID2_bn, Ti_str, message, msg_len, &sigma_i_bn, &Ri_bn);
    printf("signature generation success!\n");
    int verify_result = verify_signature(AID1, AID2_bn, alpha_i, Ti_str, message, msg_len, sigma_i_bn, Ri_bn);
    if (verify_result == 1) {
        printf("verification success\n");
    } else {
        printf("verification fail\n");
    }
    BN_free(sigma_i_bn);
    BN_free(Ri_bn);
    BN_free(ski_bn);
    BN_free(wi_bn);
    BN_free(alpha_i);
    BN_free(AID2_bn);
    EC_POINT_free(AID1);
    EC_POINT_free(P);
    EC_POINT_free(Ppub);
    BN_free(x);
    BN_free(order);
    EC_GROUP_free(ec_group);

    return 0;
}*/
char *EC_POINT_to_hex(const EC_GROUP *group, const EC_POINT *point) {
        //printf("1\n");
    size_t buf_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (buf_len == 0) {
        printf("无法获取缓冲区大小。\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    unsigned char *buf = malloc(buf_len);
    if (buf == NULL) {
        printf("内存分配失败。\n");
        return NULL;
    }

    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, buf_len, NULL) == 0) {
        printf("EC_POINT 转换为字节数组失败。\n");
        ERR_print_errors_fp(stderr);
        free(buf);
        return NULL;
    }

    char *hex = malloc(buf_len * 2 + 1); // 每个字节两个字符，外加一个空字符
    if (hex == NULL) {
        printf("内存分配失败。\n");
        free(buf);
        return NULL;
    }

    for (size_t i = 0; i < buf_len; i++) {
        sprintf(hex + i * 2, "%02X", buf[i]);
    }
    hex[buf_len * 2] = '\0'; // 添加字符串结束符

    free(buf);

    return hex;
}

EC_POINT *EC_POINT_from_hex(const EC_GROUP *group, const char *hex_str) {
    size_t buf_len = strlen(hex_str) / 2;
    unsigned char *buf = malloc(buf_len);
    if (buf == NULL) {
        printf("内存分配失败。\n");
        return NULL;
    }

    for (size_t i = 0; i < buf_len; i++) {
        sscanf(hex_str + i * 2, "%2hhx", &buf[i]);
    }

    EC_POINT *point = EC_POINT_new(group);
    if (point == NULL) {
        printf("创建 EC_POINT 失败。\n");
        ERR_print_errors_fp(stderr);
        free(buf);
        return NULL;
    }

    if (!EC_POINT_oct2point(group, point, buf, buf_len, NULL)) {
        printf("字节数组转换为 EC_POINT 失败。\n");
        ERR_print_errors_fp(stderr);
        EC_POINT_free(point);
        free(buf);
        return NULL;
    }

    free(buf);

    return point;
}
