#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define KEY_LENGTH 256
#define MAX_TEXT_LENGTH 1024

// 函数声明
int validateDecryptionKey(const char *userKey);
int hexToByte(const char *hex, unsigned char *output, int maxLength);
void generateKeyStream(const char *userKey, unsigned char *keyStream, int operationType, int transformType);
void decryptData(const unsigned char *encryptedData, const unsigned char *keyStream, 
                 char *decryptedResult, int dataLength, int operationType);
void parseFirstChar(char firstChar, int *operationType, int *transformType);
void transformKey(char *key, int transformType, char firstChar);
void clearInputBuffer();

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    
    printf("========= 数据解密程序 =========\n\n");
    
    char hexInput[MAX_TEXT_LENGTH * 2 + 1];
    char userKey[7];
    char workingKey[6];
    unsigned char keyStream[KEY_LENGTH];
    unsigned char encryptedData[MAX_TEXT_LENGTH];
    char decryptedResult[MAX_TEXT_LENGTH];
    int dataLength;
    
    while(1) {
        printf("请输入加密后的十六进制数据: ");
        fflush(stdout);
        
        if (fgets(hexInput, sizeof(hexInput), stdin) == NULL) {
            printf("读取输入失败！\n");
            clearInputBuffer();
            continue;
        }
        
        hexInput[strcspn(hexInput, "\n")] = 0;
        
        if (strcmp(hexInput, "exit") == 0 || strcmp(hexInput, "quit") == 0) {
            printf("程序结束！\n");
            break;
        }
        
        if (strlen(hexInput) == 0) {
            printf("输入不能为空！\n\n");
            continue;
        }
        
        dataLength = hexToByte(hexInput, encryptedData, MAX_TEXT_LENGTH);
        if (dataLength == 0) {
            printf("错误：无效的十六进制数据！\n\n");
            clearInputBuffer();
            continue;
        }
        
        printf("请输入6位解密密钥: ");
        fflush(stdout);
        
        if (fgets(userKey, sizeof(userKey), stdin) == NULL) {
            printf("读取密钥失败！\n");
            clearInputBuffer();
            continue;
        }
        
        userKey[strcspn(userKey, "\n")] = 0;
        
        if (strlen(userKey) != 6) {
            printf("错误：密钥必须是6位字符！\n\n");
            clearInputBuffer();
            continue;
        }
        
        if (!validateDecryptionKey(userKey)) {
            printf("错误：密钥只能包含数字(0-9)和英文字母(a-z, A-Z)！\n\n");
            clearInputBuffer();
            continue;
        }
        
        // 解析第一个字符，确定运算类型和变换类型
        int operationType, transformType;
        parseFirstChar(userKey[0], &operationType, &transformType);
        
        // 复制后5位密钥
        strcpy(workingKey, userKey + 1);
        
        // 应用密钥变换（必须与加密时相同）
        transformKey(workingKey, transformType, userKey[0]);
        
        // 生成密钥流（必须与加密时相同）
        generateKeyStream(workingKey, keyStream, operationType, transformType);
        
        // 解密数据
        decryptData(encryptedData, keyStream, decryptedResult, dataLength, operationType);
        
        // 显示解密结果
        printf("\n=== 解密成功 ===\n");
        printf("解密结果: %s\n", decryptedResult);
        printf("====================\n\n");
        
        clearInputBuffer();
    }
    
    return 0;
}

void clearInputBuffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int validateDecryptionKey(const char *userKey) {
    for(int i = 0; i < 6; i++) {
        char c = userKey[i];
        if(!((c >= '0' && c <= '9') || 
             (c >= 'a' && c <= 'z') || 
             (c >= 'A' && c <= 'Z'))) {
            return 0;
        }
    }
    return 1;
}

int hexToByte(const char *hex, unsigned char *output, int maxLength) {
    int hexLength = (int)strlen(hex);
    
    if(hexLength % 2 != 0) {
        return 0;
    }
    
    int byteLength = hexLength / 2;
    if(byteLength > maxLength) {
        return 0;
    }
    
    for(int i = 0; i < byteLength; i++) {
        char hexByte[3] = {hex[i*2], hex[i*2+1], '\0'};
        
        if(!isxdigit((unsigned char)hexByte[0]) || !isxdigit((unsigned char)hexByte[1])) {
            return 0;
        }
        
        output[i] = (unsigned char)strtol(hexByte, NULL, 16);
    }
    
    return byteLength;
}

void parseFirstChar(char firstChar, int *operationType, int *transformType) {
    int index;
    if (firstChar >= '0' && firstChar <= '9') {
        index = firstChar - '0';
    } else if (firstChar >= 'A' && firstChar <= 'Z') {
        index = 10 + (firstChar - 'A');
    } else if (firstChar >= 'a' && firstChar <= 'z') {
        index = 36 + (firstChar - 'a');
    } else {
        index = 0;
    }
    
    if ((firstChar >= '0' && firstChar <= '9') || 
        (firstChar >= 'A' && firstChar <= 'J') || 
        (firstChar >= 'a' && firstChar <= 'j')) {
        *operationType = 0;
    } else if ((firstChar >= 'K' && firstChar <= 'T') || 
               (firstChar >= 'k' && firstChar <= 't')) {
        *operationType = 1;
    } else if ((firstChar >= 'U' && firstChar <= 'Z') || 
               (firstChar >= 'u' && firstChar <= 'z')) {
        *operationType = 2;
    } else {
        *operationType = 3;
    }
    
    *transformType = index % 8;
}

void transformKey(char *key, int transformType, char firstChar) {
    int len = 5;
    
    switch(transformType) {
        case 0: break;
        case 1: 
            {
                char temp = key[0];
                for(int i = 0; i < len - 1; i++) key[i] = key[i + 1];
                key[len - 1] = temp;
            }
            break;
        case 2: 
            {
                char temp = key[len - 1];
                for(int i = len - 1; i > 0; i--) key[i] = key[i - 1];
                key[0] = temp;
            }
            break;
        case 3: 
            {
                for(int i = 0; i < len / 2; i++) {
                    char temp = key[i];
                    key[i] = key[len - 1 - i];
                    key[len - 1 - i] = temp;
                }
            }
            break;
        case 4: 
            {
                for(int i = 0; i < len - 1; i += 2) {
                    char temp = key[i];
                    key[i] = key[i + 1];
                    key[i + 1] = temp;
                }
            }
            break;
        case 5: 
            {
                for(int i = 0; i < len; i++) {
                    if (key[i] >= 'a' && key[i] <= 'z') {
                        key[i] = key[i] - 'a' + 'A';
                    } else if (key[i] >= 'A' && key[i] <= 'Z') {
                        key[i] = key[i] - 'A' + 'a';
                    }
                }
            }
            break;
        case 6: 
            {
                int offset = firstChar % 10;
                for(int i = 0; i < len; i++) {
                    if (key[i] >= '0' && key[i] <= '9') {
                        key[i] = '0' + ((key[i] - '0' + offset) % 10);
                    }
                }
            }
            break;
        case 7: 
            {
                int shift = (firstChar % 26);
                for(int i = 0; i < len; i++) {
                    if (key[i] >= 'a' && key[i] <= 'z') {
                        key[i] = 'a' + ((key[i] - 'a' + shift) % 26);
                    } else if (key[i] >= 'A' && key[i] <= 'Z') {
                        key[i] = 'A' + ((key[i] - 'A' + shift) % 26);
                    }
                }
            }
            break;
        default: break;
    }
}

void generateKeyStream(const char *userKey, unsigned char *keyStream, int operationType, int transformType) {
    int keyLength = (int)strlen(userKey);
    
    for(int i = 0; i < KEY_LENGTH; i++) {
        keyStream[i] = (unsigned char)i;
    }
    
    for(int i = 0; i < KEY_LENGTH; i++) {
        int swapPosition;
        
        switch(operationType) {
            case 0: 
                swapPosition = (userKey[i % keyLength] + i * 7 + transformType * 13) % KEY_LENGTH;
                break;
            case 1: 
                swapPosition = (userKey[i % keyLength] - i * 5 + transformType * 17 + KEY_LENGTH) % KEY_LENGTH;
                break;
            case 2: 
                swapPosition = (userKey[i % keyLength] ^ i * 3 ^ transformType * 11) % KEY_LENGTH;
                break;
            case 3: 
                swapPosition = (userKey[i % keyLength] * (i + 1) * (transformType + 1)) % KEY_LENGTH;
                break;
            default: 
                swapPosition = (userKey[i % keyLength] + i * 7) % KEY_LENGTH;
        }
        
        if(swapPosition < 0) swapPosition += KEY_LENGTH;
        if(swapPosition >= KEY_LENGTH) swapPosition %= KEY_LENGTH;
        
        unsigned char temp = keyStream[i];
        keyStream[i] = keyStream[swapPosition];
        keyStream[swapPosition] = temp;
    }
    
    for(int round = 0; round < 3; round++) {
        for(int i = 0; i < KEY_LENGTH; i++) {
            int complexIndex;
            
            switch(operationType) {
                case 0:
                    complexIndex = (userKey[(i + round) % keyLength] + 
                                  keyStream[(i + 100) % KEY_LENGTH] + 
                                  transformType * 19) % KEY_LENGTH;
                    break;
                case 1:
                    complexIndex = (userKey[(i + round) % keyLength] - 
                                  keyStream[(i + 100) % KEY_LENGTH] + 
                                  transformType * 23 + KEY_LENGTH) % KEY_LENGTH;
                    break;
                case 2:
                    complexIndex = (userKey[(i + round) % keyLength] ^ 
                                  keyStream[(i + 100) % KEY_LENGTH] ^ 
                                  transformType * 29) % KEY_LENGTH;
                    break;
                case 3:
                    complexIndex = (userKey[(i + round) % keyLength] * 
                                  (keyStream[(i + 100) % KEY_LENGTH] + 1) * 
                                  (transformType + 2)) % KEY_LENGTH;
                    break;
                default:
                    complexIndex = (userKey[(i + round) % keyLength] + 
                                  keyStream[(i + 100) % KEY_LENGTH]) % KEY_LENGTH;
            }
            
            unsigned char temp = keyStream[i];
            keyStream[i] = keyStream[complexIndex];
            keyStream[complexIndex] = temp;
        }
    }
}

void decryptData(const unsigned char *encryptedData, const unsigned char *keyStream, 
                 char *decryptedResult, int dataLength, int operationType) {
    for(int i = 0; i < dataLength; i++) {
        unsigned char encryptedByte = encryptedData[i];
        unsigned char keyByte = keyStream[i % KEY_LENGTH];
        
        switch(operationType) {
            case 0:
                decryptedResult[i] = (encryptedByte - keyByte + 256) % 256;
                break;
            case 1:
                decryptedResult[i] = (encryptedByte + keyByte) % 256;
                break;
            case 2:
                decryptedResult[i] = encryptedByte ^ keyByte;
                break;
            case 3:
                if(keyByte == 0) keyByte = 1;
                for(int j = 0; j < 256; j++) {
                    if((j * keyByte) % 256 == encryptedByte) {
                        decryptedResult[i] = (char)j;
                        break;
                    }
                }
                break;
            default:
                decryptedResult[i] = (encryptedByte - keyByte + 256) % 256;
        }
    }
    
    decryptedResult[dataLength] = '\0';
}