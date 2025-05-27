#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring> // For memcpy, memset
#include <cstdlib> // For rand, srand
#include <ctime>   // For time

// 包含原始的 DES.cpp 文件
// 注意：这种方式在大型项目中可能导致问题。
// 标准做法是为 DES.cpp 创建一个头文件，并在那里声明函数。
#include "d:\\Project_jiami\\DES.cpp"

// 确认 ElemType 的定义与 DES.cpp 中一致，通常是 unsigned char
// typedef char ElemType; // 如果 DES.cpp 中是 char
typedef char ElemType;
// 异或两个字节块
void XOR_Blocks(ElemType* output, const ElemType* input1, const ElemType* input2, int size) {
    for (int i = 0; i < size; ++i) {
        output[i] = input1[i] ^ input2[i];
    }
}

// PKCS#7 填充
// dataSize 是当前块中实际数据的字节数 (0-7)
// 返回添加的填充字节数 (1-8)
int PKCS7_Padding(ElemType* block, int dataSize) {
    int paddingSize = 8 - dataSize;
    // 如果 dataSize == 0，表示输入块是空的 (只在文件大小是8的倍数时需要额外填充一个全8的块)
    // 如果 dataSize > 0 且 < 8，填充字节数为 8 - dataSize
    // 如果 dataSize == 8，表示输入块是满的，需要添加一个新块，全填充 (8字节都是8)
    // 这里的实现是处理不足8字节的最后一个块。如果文件大小是8的倍数，需要在循环外处理。

    // 此函数用于填充一个不足8字节的块
    // 实际上，更通用的PKCS#7填充逻辑应该在处理文件流时判断，并在必要时添加一个全填充块。
    // 我们将填充逻辑整合到文件处理函数中。
    return 0; // 这个函数不再单独使用，逻辑移入文件处理函数
}

// PKCS#7 去填充
// block 是一个完整的8字节块，解密后的数据
// dataSize 是输出的实际数据大小 (通过指针返回)
// 返回 0 表示成功，-1 表示填充无效
int PKCS7_Unpadding(const ElemType* block, int* dataSize) {
    // 根据PKCS#7规范，最后一个字节的值就是填充的字节数
    int paddingSize = block[7];

    // 填充字节数必须在1到8之间
    if (paddingSize < 1 || paddingSize > 8) {
        // 无效的填充值
        std::cerr << "Error: Invalid padding size: " << paddingSize << std::endl;
        return -1;
    }

    // 检查最后的 paddingSize 个字节是否都等于 paddingSize 的值
    for (int i = 8 - paddingSize; i < 8; ++i) {
        if (block[i] != (ElemType)paddingSize) {
            // 填充内容不符合规范
            std::cerr << "Error: Invalid padding byte at position " << i << " (expected " << paddingSize << ", got " << (int)block[i] << ")" << std::endl;
            return -1;
        }
    }

    // 如果填充有效，实际数据大小就是 8 - paddingSize
    *dataSize = 8 - paddingSize;
    return 0; // 成功去填充
}


// CBC模式文件加密
int encrypt_file_cbc(const std::string& plainFile, const std::string& keyStr, const std::string& cipherFile) {
    std::ifstream ifp(plainFile, std::ios::binary);
    std::ofstream ofp(cipherFile, std::ios::binary);

    if (!ifp) {
        std::cerr << "Error: Cannot open input file " << plainFile << std::endl;
        return -1; // 使用自定义错误码或标准库错误处理
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

    // 准备子密钥 (调用 DES.cpp 中的函数)
    ElemType keyBits[64];
    ElemType subKeys[16][48];
    Char8ToBit64((ElemType*)keyStr.c_str(), keyBits); // 假设 Char8ToBit64 在 DES.cpp 中且可用
    DES_MakeSubKeys(keyBits, subKeys); // 假设 DES_MakeSubKeys 在 DES.cpp 中且可用

    // 生成随机IV并写入密文文件头部
    ElemType iv[8], current_iv[8];
    srand(time(NULL)); // 初始化随机数种子
    for (int i = 0; i < 8; ++i) {
        iv[i] = rand() % 256; // 生成随机字节
    }
    ofp.write((char*)iv, 8); // 将IV写入密文文件头部
    memcpy(current_iv, iv, 8); // 第一个块的IV是随机生成的IV

    ElemType plainBlock[8], cipherBlock[8];
    std::streamsize bytesRead;

    // 获取文件大小用于填充判断
    ifp.seekg(0, std::ios::end);
    long fileSize = ifp.tellg();
    ifp.seekg(0, std::ios::beg); // 回到文件开头

    long currentReadPos = 0;

    // 分块读取、加密、写入
    while (currentReadPos < fileSize) {
        bytesRead = ifp.read((char*)plainBlock, 8).gcount();

        // CBC: 明文块与当前IV异或
        XOR_Blocks(plainBlock, plainBlock, current_iv, bytesRead); // 只对读取的数据部分异或

        if (currentReadPos + bytesRead == fileSize) {
            // 这是最后一个块 (可能不足8字节)，需要填充
            int paddingSize = 8 - bytesRead;
            // 如果文件大小是8的倍数，bytesRead将是8，paddingSize将是0。
            // PKCS#7规定此时需要加一个全8的新块。我们在这里处理不足8字节的情况。
            // 如果 bytesRead == 8 且是最后一个块，在循环外添加全8的填充块。
            if (bytesRead < 8) {
                int actualPaddingSize = 8 - bytesRead; // 1 to 7
                for (int i = bytesRead; i < 8; ++i) {
                    plainBlock[i] = (ElemType)actualPaddingSize;
                }
                bytesRead = 8; // 填充后处理为完整块
            }
        }

        // DES 分组加密 (假设 plainBlock 此时已经是完整的8字节块，可能包含填充)
        DES_EncryptBlock(plainBlock, subKeys, cipherBlock); // 假设 DES_EncryptBlock 在 DES.cpp 中且可用

        // 写入密文块
        ofp.write((char*)cipherBlock, 8);

        // 更新IV为当前生成的密文块
        memcpy(current_iv, cipherBlock, 8);

        currentReadPos += bytesRead; // 更新当前读取位置 (对于填充后的块，按8字节计算)
    }

    // 如果明文文件大小是8的倍数，需要添加一个完整的填充块
    if (fileSize > 0 && fileSize % 8 == 0) {
        ElemType paddingBlock[8];
        int paddingSize = 8; // PKCS#7: 8字节全填充
        for (int i = 0; i < 8; ++i) {
            paddingBlock[i] = (ElemType)paddingSize;
        }

        // CBC: 填充块与前一个密文块异或
        XOR_Blocks(paddingBlock, paddingBlock, current_iv, 8);

        // DES 分组加密
        DES_EncryptBlock(paddingBlock, subKeys, cipherBlock);

        // 写入密文块
        ofp.write((char*)cipherBlock, 8);
        // current_iv 无需更新，因为这是最后一个块
    }


    ifp.close();
    ofp.close();

    std::cout << "File encrypted successfully: " << cipherFile << std::endl;
    return 0; // 成功返回0
}

// CBC模式文件解密
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

    // 准备子密钥 (调用 DES.cpp 中的函数)
    ElemType keyBits[64];
    ElemType subKeys[16][48];
    Char8ToBit64((ElemType*)keyStr.c_str(), keyBits); // 假设 Char8ToBit64 在 DES.cpp 中且可用
    DES_MakeSubKeys(keyBits, subKeys); // 假设 DES_MakeSubKeys 在 DES.cpp 中且可用

    ElemType iv[8], current_iv[8];
    // 从密文文件头部读取IV
    ifp.read((char*)iv, 8);
    std::streamsize bytesReadIV = ifp.gcount();
    if (bytesReadIV != 8) {
        std::cerr << "Error: Failed to read IV from cipher file or file is too small." << std::endl;
        ifp.close();
        ofp.close();
        return -1; // 读取IV失败或文件太小
    }
    memcpy(current_iv, iv, 8); // 第一个块解密用的IV

    ElemType cipherBlock[8], plainBlock[8], previousCipherBlock[8];
    std::streamsize bytesRead;
    long fileSize;

    // 获取密文文件大小 (包括IV)
    ifp.seekg(0, std::ios::end);
    fileSize = ifp.tellg();
    ifp.seekg(8, std::ios::beg); // 回到IV后面开始读第一个密文块

    // 密文文件大小必须是 8 + N*8 的形式 (IV + 多个分组)
    if ((fileSize - 8) % 8 != 0 || fileSize < 8) {
        std::cerr << "Error: Invalid cipher file size. Must be 8 + multiple of 8." << std::endl;
        ifp.close();
        ofp.close();
        return -1;
    }

    long currentReadPos = 8; // 当前读取位置 (从文件开头算起，跳过IV)

    // 分块读取、解密、写入
    while (currentReadPos < fileSize) {
        bytesRead = ifp.read((char*)cipherBlock, 8).gcount();
        if (bytesRead != 8) {
            // 理论上除了文件结束，都应该读取到完整的8字节密文块
            std::cerr << "Error: Unexpected bytes read: " << bytesRead << " at position: " << currentReadPos << std::endl;
            return -1; // 读取异常
        }

        memcpy(previousCipherBlock, cipherBlock, 8); // 保存当前密文块，用于下一次异或

        // DES 分组解密
        DES_DecryptBlock(cipherBlock, subKeys, plainBlock); // 假设 DES_DecryptBlock 在 DES.cpp 中且可用

        // CBC: 解密结果与当前IV异或
        XOR_Blocks(plainBlock, plainBlock, current_iv, 8);

        // 更新IV为当前读取的密文块 (下一个块解密时用)
        memcpy(current_iv, previousCipherBlock, 8);

        currentReadPos += bytesRead; // 更新当前读取位置

        // 写入明文块 (最后一个块需要去填充)
        if (currentReadPos == fileSize) { // 这是最后一个块 (密文部分)
            int plainDataSize = 0;
            if (PKCS7_Unpadding(plainBlock, &plainDataSize) == 0) {
                ofp.write((char*)plainBlock, plainDataSize);
            }
            else {
                // 去填充失败，可能密钥错误或密文被篡改
                std::cerr << "Error: Padding removal failed. Key might be incorrect or cipher file corrupted." << std::endl;
                // 清空已写入的不完整文件 (可选，取决于需求)
                ofp.close();
                // remove(plainFile.c_str());
                return -1; // 去填充失败
            }
        }
        else {
            ofp.write((char*)plainBlock, 8); // 中间的块直接写入完整的8字节
        }
    }

    ifp.close();
    ofp.close();

    std::cout << "File decrypted successfully: " << plainFile << std::endl;
    return 0; // 成功返回0
}

// 主函数，处理命令行参数
int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <mode> <input_file> <output_file> <key>" << std::endl;
        std::cerr << "  <mode>: encrypt or decrypt" << std::endl;
        std::cerr << "  <key>: 8 bytes key string" << std::endl;
        return 1; // 参数错误返回非0
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string key = argv[4];

    if (key.length() != 8) {
        std::cerr << "Error: Key must be exactly 8 bytes." << std::endl;
        return 1; // 密钥长度错误返回非0
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
        return 1; // 模式错误返回非0
    }

    return result; // 返回加密/解密函数的执行结果
}