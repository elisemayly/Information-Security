#include <stdio.h>
#include <string.h>
#include "DES.cpp"  

int main() {
    // ���� 8 �ֽڵ����ĺ���Կ
    unsigned char key[8] = { 's', 'e', 'c', 'r', 'e', 't', 'k', 'y' };  // 8�ֽ���Կ
    unsigned char plaintext[8] = { 'A', 'B', 'C', 'D', '1', '2', '3', '4' }; // 8�ֽ�����
    unsigned char ciphertext[8];
    unsigned char decrypted[8];

    // ����
    DES_Encrypt(plaintext, ciphertext, key);
    printf("���ܺ�����ģ�ʮ�����ƣ�: ");
    for (int i = 0; i < 8; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    // ����
    DES_Decrypt(ciphertext, decrypted, key);
    printf("���ܻ�ԭ�������: ");
    for (int i = 0; i < 8; i++) {
        printf("%c", decrypted[i]);
    }
    printf("\n");

    return 0;
}