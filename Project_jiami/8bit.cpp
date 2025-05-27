#include <stdio.h>
#include <string.h>
#include "DES.cpp"  

int main() {
    // 设置 8 字节的明文和密钥
    unsigned char key[8] = { 's', 'e', 'c', 'r', 'e', 't', 'k', 'y' };  // 8字节密钥
    unsigned char plaintext[8] = { 'A', 'B', 'C', 'D', '1', '2', '3', '4' }; // 8字节明文
    unsigned char ciphertext[8];
    unsigned char decrypted[8];

    // 加密
    DES_Encrypt(plaintext, ciphertext, key);
    printf("加密后的密文（十六进制）: ");
    for (int i = 0; i < 8; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    // 解密
    DES_Decrypt(ciphertext, decrypted, key);
    printf("解密还原后的明文: ");
    for (int i = 0; i < 8; i++) {
        printf("%c", decrypted[i]);
    }
    printf("\n");

    return 0;
}