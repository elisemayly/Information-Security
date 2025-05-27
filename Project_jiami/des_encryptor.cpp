#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "DES.cpp"  

// 工具函数 

// PKCS#5 填充
int pad(unsigned char* block, int len) {
    int padLen = 8 - len;
    for (int i = len; i < 8; i++) {
        block[i] = padLen;
    }
    return 8;
}

// 解密后去填充（仅在最后一块调用）
int unpad(unsigned char* block) {
    int padLen = block[7];
    if (padLen < 1 || padLen > 8) return 0;
    return 8 - padLen;
}

//  文件加密

void encrypt_file(const char* input_path, const char* output_path, KEY_sub* key_sub) {
    FILE* fin = fopen(input_path, "rb");
    FILE* fout = fopen(output_path, "wb");

    if (!fin || !fout) {
        printf("文件打开失败！\n");
        return;
    }

    unsigned char buffer[8] = { 0 };
    unsigned char cipher[8];
    size_t read_len;

    while ((read_len = fread(buffer, 1, 8, fin)) == 8) {
        DES_EncryptBlock(buffer, cipher, key_sub);
        fwrite(cipher, 1, 8, fout);
    }

    // 最后一块处理（填充）
    if (read_len > 0 || feof(fin)) {
        pad(buffer, read_len);
        DES_EncryptBlock(buffer, cipher, key_sub);
        fwrite(cipher, 1, 8, fout);
    }

    fclose(fin);
    fclose(fout);
}

//  文件解密

void decrypt_file(const char* input_path, const char* output_path, KEY_sub* key_sub) {
    FILE* fin = fopen(input_path, "rb");
    FILE* fout = fopen(output_path, "wb");

    if (!fin || !fout) {
        printf("文件打开失败！\n");
        return;
    }

    unsigned char buffer[8];
    unsigned char plain[8];
    size_t read_len;

    // 获取文件长度，定位最后一块
    fseek(fin, 0, SEEK_END);
    long total_len = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    long pos = 0;
    while ((pos = ftell(fin)) < total_len - 8) {
        fread(buffer, 1, 8, fin);
        DES_DecryptBlock(buffer, plain, key_sub);
        fwrite(plain, 1, 8, fout);
    }

    // 解密最后一块并去填充
    fread(buffer, 1, 8, fin);
    DES_DecryptBlock(buffer, plain, key_sub);
    int unpad_len = unpad(plain);
    fwrite(plain, 1, unpad_len, fout);

    fclose(fin);
    fclose(fout);
}

//  单块加解密测试

void test_single_block(KEY_sub* key_sub) {
    unsigned char plaintext[8] = { 'T', 'e', 's', 't', 'D', 'E', 'S', '\n' };
    unsigned char ciphertext[8];
    unsigned char decrypted[8];

    printf("\n=== 单块明文加解密测试 ===\n");

    printf("原文: ");
    for (int i = 0; i < 8; i++) {
        printf("%c", plaintext[i]);
    }
    printf("\n");

    DES_EncryptBlock(plaintext, ciphertext, key_sub);
    printf("加密后: ");
    for (int i = 0; i < 8; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    DES_DecryptBlock(ciphertext, decrypted, key_sub);
    printf("解密还原: ");
    for (int i = 0; i < 8; i++) {
        printf("%c", decrypted[i]);
    }
    printf("\n");
}

//  主函数

int main() {
    // 1. 初始化密钥
    KEY key;
    KEY_sub key_sub;
    unsigned char key_bytes[8] = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
    memcpy(key.data, key_bytes, 8);
    SetKey(&key, &key_sub);

    // 2. 测试单块明文加密和解密
    test_single_block(&key_sub);

    // 3. 测试文件加密和解密
    printf("\n=== 文件加密解密测试 ===\n");

    const char* in_file = "input.txt";         // 原始明文文件
    const char* enc_file = "encrypted.des";    // 加密输出
    const char* dec_file = "decrypted.txt";    // 解密还原文件

    encrypt_file(in_file, enc_file, &key_sub);
    printf("文件加密完成，生成文件：%s\n", enc_file);

    decrypt_file(enc_file, dec_file, &key_sub);
    printf("文件解密完成，还原文件：%s\n", dec_file);

    return 0;
}
