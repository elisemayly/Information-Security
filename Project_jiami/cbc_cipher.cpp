#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring> // For memcpy, memset
#include <cstdlib> // For rand, srand
#include <ctime>   // For time

// ����ԭʼ�� DES.cpp �ļ�
// ע�⣺���ַ�ʽ�ڴ�����Ŀ�п��ܵ������⡣
// ��׼������Ϊ DES.cpp ����һ��ͷ�ļ���������������������
#include "d:\\Project_jiami\\DES.cpp"

// ȷ�� ElemType �Ķ����� DES.cpp ��һ�£�ͨ���� unsigned char
// typedef char ElemType; // ��� DES.cpp ���� char
typedef char ElemType;
// ��������ֽڿ�
void XOR_Blocks(ElemType* output, const ElemType* input1, const ElemType* input2, int size) {
    for (int i = 0; i < size; ++i) {
        output[i] = input1[i] ^ input2[i];
    }
}

// PKCS#7 ���
// dataSize �ǵ�ǰ����ʵ�����ݵ��ֽ��� (0-7)
// ������ӵ�����ֽ��� (1-8)
int PKCS7_Padding(ElemType* block, int dataSize) {
    int paddingSize = 8 - dataSize;
    // ��� dataSize == 0����ʾ������ǿյ� (ֻ���ļ���С��8�ı���ʱ��Ҫ�������һ��ȫ8�Ŀ�)
    // ��� dataSize > 0 �� < 8������ֽ���Ϊ 8 - dataSize
    // ��� dataSize == 8����ʾ����������ģ���Ҫ���һ���¿飬ȫ��� (8�ֽڶ���8)
    // �����ʵ���Ǵ�����8�ֽڵ����һ���顣����ļ���С��8�ı�������Ҫ��ѭ���⴦��

    // �˺����������һ������8�ֽڵĿ�
    // ʵ���ϣ���ͨ�õ�PKCS#7����߼�Ӧ���ڴ����ļ���ʱ�жϣ����ڱ�Ҫʱ���һ��ȫ���顣
    // ���ǽ�����߼����ϵ��ļ��������С�
    return 0; // ����������ٵ���ʹ�ã��߼������ļ�������
}

// PKCS#7 ȥ���
// block ��һ��������8�ֽڿ飬���ܺ������
// dataSize �������ʵ�����ݴ�С (ͨ��ָ�뷵��)
// ���� 0 ��ʾ�ɹ���-1 ��ʾ�����Ч
int PKCS7_Unpadding(const ElemType* block, int* dataSize) {
    // ����PKCS#7�淶�����һ���ֽڵ�ֵ���������ֽ���
    int paddingSize = block[7];

    // ����ֽ���������1��8֮��
    if (paddingSize < 1 || paddingSize > 8) {
        // ��Ч�����ֵ
        std::cerr << "Error: Invalid padding size: " << paddingSize << std::endl;
        return -1;
    }

    // ������� paddingSize ���ֽ��Ƿ񶼵��� paddingSize ��ֵ
    for (int i = 8 - paddingSize; i < 8; ++i) {
        if (block[i] != (ElemType)paddingSize) {
            // ������ݲ����Ϲ淶
            std::cerr << "Error: Invalid padding byte at position " << i << " (expected " << paddingSize << ", got " << (int)block[i] << ")" << std::endl;
            return -1;
        }
    }

    // ��������Ч��ʵ�����ݴ�С���� 8 - paddingSize
    *dataSize = 8 - paddingSize;
    return 0; // �ɹ�ȥ���
}


// CBCģʽ�ļ�����
int encrypt_file_cbc(const std::string& plainFile, const std::string& keyStr, const std::string& cipherFile) {
    std::ifstream ifp(plainFile, std::ios::binary);
    std::ofstream ofp(cipherFile, std::ios::binary);

    if (!ifp) {
        std::cerr << "Error: Cannot open input file " << plainFile << std::endl;
        return -1; // ʹ���Զ����������׼�������
    }
    if (!ofp) {
        std::cerr << "Error: Cannot open output file " << cipherFile << std::endl;
        ifp.close();
        return -1;
    }

    if (keyStr.length() != 8) {
        std::cerr << "Error: Key must be exactly 8 bytes." << std::endl;
        ifp.close();
        ofp.close();
        return -1;
    }

    // ׼������Կ (���� DES.cpp �еĺ���)
    ElemType keyBits[64];
    ElemType subKeys[16][48];
    Char8ToBit64((ElemType*)keyStr.c_str(), keyBits); // ���� Char8ToBit64 �� DES.cpp ���ҿ���
    DES_MakeSubKeys(keyBits, subKeys); // ���� DES_MakeSubKeys �� DES.cpp ���ҿ���

    // �������IV��д�������ļ�ͷ��
    ElemType iv[8], current_iv[8];
    srand(time(NULL)); // ��ʼ�����������
    for (int i = 0; i < 8; ++i) {
        iv[i] = rand() % 256; // ��������ֽ�
    }
    ofp.write((char*)iv, 8); // ��IVд�������ļ�ͷ��
    memcpy(current_iv, iv, 8); // ��һ�����IV��������ɵ�IV

    ElemType plainBlock[8], cipherBlock[8];
    std::streamsize bytesRead;

    // ��ȡ�ļ���С��������ж�
    ifp.seekg(0, std::ios::end);
    long fileSize = ifp.tellg();
    ifp.seekg(0, std::ios::beg); // �ص��ļ���ͷ

    long currentReadPos = 0;

    // �ֿ��ȡ�����ܡ�д��
    while (currentReadPos < fileSize) {
        bytesRead = ifp.read((char*)plainBlock, 8).gcount();

        // CBC: ���Ŀ��뵱ǰIV���
        XOR_Blocks(plainBlock, plainBlock, current_iv, bytesRead); // ֻ�Զ�ȡ�����ݲ������

        if (currentReadPos + bytesRead == fileSize) {
            // �������һ���� (���ܲ���8�ֽ�)����Ҫ���
            int paddingSize = 8 - bytesRead;
            // ����ļ���С��8�ı�����bytesRead����8��paddingSize����0��
            // PKCS#7�涨��ʱ��Ҫ��һ��ȫ8���¿顣���������ﴦ����8�ֽڵ������
            // ��� bytesRead == 8 �������һ���飬��ѭ�������ȫ8�����顣
            if (bytesRead < 8) {
                int actualPaddingSize = 8 - bytesRead; // 1 to 7
                for (int i = bytesRead; i < 8; ++i) {
                    plainBlock[i] = (ElemType)actualPaddingSize;
                }
                bytesRead = 8; // ������Ϊ������
            }
        }

        // DES ������� (���� plainBlock ��ʱ�Ѿ���������8�ֽڿ飬���ܰ������)
        DES_EncryptBlock(plainBlock, subKeys, cipherBlock); // ���� DES_EncryptBlock �� DES.cpp ���ҿ���

        // д�����Ŀ�
        ofp.write((char*)cipherBlock, 8);

        // ����IVΪ��ǰ���ɵ����Ŀ�
        memcpy(current_iv, cipherBlock, 8);

        currentReadPos += bytesRead; // ���µ�ǰ��ȡλ�� (��������Ŀ飬��8�ֽڼ���)
    }

    // ��������ļ���С��8�ı�������Ҫ���һ������������
    if (fileSize > 0 && fileSize % 8 == 0) {
        ElemType paddingBlock[8];
        int paddingSize = 8; // PKCS#7: 8�ֽ�ȫ���
        for (int i = 0; i < 8; ++i) {
            paddingBlock[i] = (ElemType)paddingSize;
        }

        // CBC: ������ǰһ�����Ŀ����
        XOR_Blocks(paddingBlock, paddingBlock, current_iv, 8);

        // DES �������
        DES_EncryptBlock(paddingBlock, subKeys, cipherBlock);

        // д�����Ŀ�
        ofp.write((char*)cipherBlock, 8);
        // current_iv ������£���Ϊ�������һ����
    }


    ifp.close();
    ofp.close();

    std::cout << "File encrypted successfully: " << cipherFile << std::endl;
    return 0; // �ɹ�����0
}

// CBCģʽ�ļ�����
int decrypt_file_cbc(const std::string& cipherFile, const std::string& keyStr, const std::string& plainFile) {
    std::ifstream ifp(cipherFile, std::ios::binary);
    std::ofstream ofp(plainFile, std::ios::binary);

    if (!ifp) {
        std::cerr << "Error: Cannot open input file " << cipherFile << std::endl;
        return -1;
    }
    if (!ofp) {
        std::cerr << "Error: Cannot open output file " << plainFile << std::endl;
        ifp.close();
        return -1;
    }

    if (keyStr.length() != 8) {
        std::cerr << "Error: Key must be exactly 8 bytes." << std::endl;
        ifp.close();
        ofp.close();
        return -1;
    }

    // ׼������Կ (���� DES.cpp �еĺ���)
    ElemType keyBits[64];
    ElemType subKeys[16][48];
    Char8ToBit64((ElemType*)keyStr.c_str(), keyBits); // ���� Char8ToBit64 �� DES.cpp ���ҿ���
    DES_MakeSubKeys(keyBits, subKeys); // ���� DES_MakeSubKeys �� DES.cpp ���ҿ���

    ElemType iv[8], current_iv[8];
    // �������ļ�ͷ����ȡIV
    ifp.read((char*)iv, 8);
    std::streamsize bytesReadIV = ifp.gcount();
    if (bytesReadIV != 8) {
        std::cerr << "Error: Failed to read IV from cipher file or file is too small." << std::endl;
        ifp.close();
        ofp.close();
        return -1; // ��ȡIVʧ�ܻ��ļ�̫С
    }
    memcpy(current_iv, iv, 8); // ��һ��������õ�IV

    ElemType cipherBlock[8], plainBlock[8], previousCipherBlock[8];
    std::streamsize bytesRead;
    long fileSize;

    // ��ȡ�����ļ���С (����IV)
    ifp.seekg(0, std::ios::end);
    fileSize = ifp.tellg();
    ifp.seekg(8, std::ios::beg); // �ص�IV���濪ʼ����һ�����Ŀ�

    // �����ļ���С������ 8 + N*8 ����ʽ (IV + �������)
    if ((fileSize - 8) % 8 != 0 || fileSize < 8) {
        std::cerr << "Error: Invalid cipher file size. Must be 8 + multiple of 8." << std::endl;
        ifp.close();
        ofp.close();
        return -1;
    }

    long currentReadPos = 8; // ��ǰ��ȡλ�� (���ļ���ͷ��������IV)

    // �ֿ��ȡ�����ܡ�д��
    while (currentReadPos < fileSize) {
        bytesRead = ifp.read((char*)cipherBlock, 8).gcount();
        if (bytesRead != 8) {
            // �����ϳ����ļ���������Ӧ�ö�ȡ��������8�ֽ����Ŀ�
            std::cerr << "Error: Unexpected bytes read: " << bytesRead << " at position: " << currentReadPos << std::endl;
            return -1; // ��ȡ�쳣
        }

        memcpy(previousCipherBlock, cipherBlock, 8); // ���浱ǰ���Ŀ飬������һ�����

        // DES �������
        DES_DecryptBlock(cipherBlock, subKeys, plainBlock); // ���� DES_DecryptBlock �� DES.cpp ���ҿ���

        // CBC: ���ܽ���뵱ǰIV���
        XOR_Blocks(plainBlock, plainBlock, current_iv, 8);

        // ����IVΪ��ǰ��ȡ�����Ŀ� (��һ�������ʱ��)
        memcpy(current_iv, previousCipherBlock, 8);

        currentReadPos += bytesRead; // ���µ�ǰ��ȡλ��

        // д�����Ŀ� (���һ������Ҫȥ���)
        if (currentReadPos == fileSize) { // �������һ���� (���Ĳ���)
            int plainDataSize = 0;
            if (PKCS7_Unpadding(plainBlock, &plainDataSize) == 0) {
                ofp.write((char*)plainBlock, plainDataSize);
            }
            else {
                // ȥ���ʧ�ܣ�������Կ��������ı��۸�
                std::cerr << "Error: Padding removal failed. Key might be incorrect or cipher file corrupted." << std::endl;
                // �����д��Ĳ������ļ� (��ѡ��ȡ��������)
                ofp.close();
                // remove(plainFile.c_str());
                return -1; // ȥ���ʧ��
            }
        }
        else {
            ofp.write((char*)plainBlock, 8); // �м�Ŀ�ֱ��д��������8�ֽ�
        }
    }

    ifp.close();
    ofp.close();

    std::cout << "File decrypted successfully: " << plainFile << std::endl;
    return 0; // �ɹ�����0
}

// �����������������в���
int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <mode> <input_file> <output_file> <key>" << std::endl;
        std::cerr << "  <mode>: encrypt or decrypt" << std::endl;
        std::cerr << "  <key>: 8 bytes key string" << std::endl;
        return 1; // �������󷵻ط�0
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string key = argv[4];

    if (key.length() != 8) {
        std::cerr << "Error: Key must be exactly 8 bytes." << std::endl;
        return 1; // ��Կ���ȴ��󷵻ط�0
    }

    int result = 0;
    if (mode == "encrypt") {
        result = encrypt_file_cbc(inputFile, key, outputFile);
    }
    else if (mode == "decrypt") {
        result = decrypt_file_cbc(inputFile, key, outputFile);
    }
    else {
        std::cerr << "Error: Invalid mode. Use 'encrypt' or 'decrypt'." << std::endl;
        return 1; // ģʽ���󷵻ط�0
    }

    return result; // ���ؼ���/���ܺ�����ִ�н��
}