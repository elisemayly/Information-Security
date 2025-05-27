#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "DES.cpp"  

// ���ߺ��� 

// PKCS#5 ���
int pad(unsigned char* block, int len) {
    int padLen = 8 - len;
    for (int i = len; i < 8; i++) {
        block[i] = padLen;
    }
    return 8;
}

// ���ܺ�ȥ��䣨�������һ����ã�
int unpad(unsigned char* block) {
    int padLen = block[7];
    if (padLen < 1 || padLen > 8) return 0;
    return 8 - padLen;
}

//  �ļ�����

void encrypt_file(const char* input_path, const char* output_path, KEY_sub* key_sub) {
    FILE* fin = fopen(input_path, "rb");
    FILE* fout = fopen(output_path, "wb");

    if (!fin || !fout) {
        printf("�ļ���ʧ�ܣ�\n");
        return;
    }

    unsigned char buffer[8] = { 0 };
    unsigned char cipher[8];
    size_t read_len;

    while ((read_len = fread(buffer, 1, 8, fin)) == 8) {
        DES_EncryptBlock(buffer, cipher, key_sub);
        fwrite(cipher, 1, 8, fout);
    }

    // ���һ�鴦����䣩
    if (read_len > 0 || feof(fin)) {
        pad(buffer, read_len);
        DES_EncryptBlock(buffer, cipher, key_sub);
        fwrite(cipher, 1, 8, fout);
    }

    fclose(fin);
    fclose(fout);
}

//  �ļ�����

void decrypt_file(const char* input_path, const char* output_path, KEY_sub* key_sub) {
    FILE* fin = fopen(input_path, "rb");
    FILE* fout = fopen(output_path, "wb");

    if (!fin || !fout) {
        printf("�ļ���ʧ�ܣ�\n");
        return;
    }

    unsigned char buffer[8];
    unsigned char plain[8];
    size_t read_len;

    // ��ȡ�ļ����ȣ���λ���һ��
    fseek(fin, 0, SEEK_END);
    long total_len = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    long pos = 0;
    while ((pos = ftell(fin)) < total_len - 8) {
        fread(buffer, 1, 8, fin);
        DES_DecryptBlock(buffer, plain, key_sub);
        fwrite(plain, 1, 8, fout);
    }

    // �������һ�鲢ȥ���
    fread(buffer, 1, 8, fin);
    DES_DecryptBlock(buffer, plain, key_sub);
    int unpad_len = unpad(plain);
    fwrite(plain, 1, unpad_len, fout);

    fclose(fin);
    fclose(fout);
}

//  ����ӽ��ܲ���

void test_single_block(KEY_sub* key_sub) {
    unsigned char plaintext[8] = { 'T', 'e', 's', 't', 'D', 'E', 'S', '\n' };
    unsigned char ciphertext[8];
    unsigned char decrypted[8];

    printf("\n=== �������ļӽ��ܲ��� ===\n");

    printf("ԭ��: ");
    for (int i = 0; i < 8; i++) {
        printf("%c", plaintext[i]);
    }
    printf("\n");

    DES_EncryptBlock(plaintext, ciphertext, key_sub);
    printf("���ܺ�: ");
    for (int i = 0; i < 8; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    DES_DecryptBlock(ciphertext, decrypted, key_sub);
    printf("���ܻ�ԭ: ");
    for (int i = 0; i < 8; i++) {
        printf("%c", decrypted[i]);
    }
    printf("\n");
}

//  ������

int main() {
    // 1. ��ʼ����Կ
    KEY key;
    KEY_sub key_sub;
    unsigned char key_bytes[8] = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
    memcpy(key.data, key_bytes, 8);
    SetKey(&key, &key_sub);

    // 2. ���Ե������ļ��ܺͽ���
    test_single_block(&key_sub);

    // 3. �����ļ����ܺͽ���
    printf("\n=== �ļ����ܽ��ܲ��� ===\n");

    const char* in_file = "input.txt";         // ԭʼ�����ļ�
    const char* enc_file = "encrypted.des";    // �������
    const char* dec_file = "decrypted.txt";    // ���ܻ�ԭ�ļ�

    encrypt_file(in_file, enc_file, &key_sub);
    printf("�ļ�������ɣ������ļ���%s\n", enc_file);

    decrypt_file(enc_file, dec_file, &key_sub);
    printf("�ļ�������ɣ���ԭ�ļ���%s\n", dec_file);

    return 0;
}
