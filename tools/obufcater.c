#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern void* chacha20_Full(void* message, void* out_message, int length);

int match_pattern(const unsigned char* buf, int len) {
    // Check fixed bytes only — skip index 8 (wildcard)
    if (len < 13) return 0;

    if (buf[0] != 0x41) return 0; 
    if (buf[1] != 0x5a) return 0;
    if (buf[2] != 0x49) return 0;
    if (buf[3] != 0x83) return 0;
    if (buf[4] != 0xc2) return 0;
    if (buf[5] != 0x11) return 0;
    if (buf[6] != 0x41) return 0;
    if (buf[7] != 0xbd) return 0;
    // buf[8] = wildcard (any)
    if (buf[9] != 0x00) return 0;
    if (buf[10] != 0x00) return 0;
    if (buf[11] != 0x00) return 0;
    if (buf[12] != 0xe8) return 0;

    return 1; // matched
}


int main(){
    FILE* file = fopen("../../gostInit/bin/core.bin", "rb");
    if (!file) {
        perror("[-] Failed to open .bin");
    }

    unsigned char file_buffer[7000];
    unsigned char write_buffer[7000];
    size_t bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file);
    fseek(file, 0, SEEK_SET);
     size_t bytes_read2 = fread(write_buffer, 1, sizeof(write_buffer), file);
    fclose(file);

    if (bytes_read == 0) {
        fprintf(stderr, "[-] No bytes read from file, nothing to write\n");
        return 1;
    }


    for(int i=0; i < bytes_read; i++){
        if (match_pattern(&file_buffer[i], 13) == 1) {
            chacha20_Full(&write_buffer[i+17], &write_buffer[i+17], (int)write_buffer[i+8]);
            printf("Encrypted %d bytes\n",file_buffer[i+8]);
        }
        
    }

    // for(int j = 0; j < bytes_read; j++){
    //     printf("%c",file_buffer[j]);
    // }

    file = fopen("../../gostInit/bin/core.bin", "wb");
    if (!file) {
        perror("[-] Failed to open .bin");
    }

    size_t bytes_written = fwrite(write_buffer, 1, bytes_read, file);
    fclose(file);
    if (bytes_written != bytes_read) {
        perror("[-] Failed to write all bytes");
    }
    printf("[+] File overwritten successfully\n");
}