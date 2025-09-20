#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_GOLDEN_YELLOW "\x1b[38;5;214m"
#define COLOR_RESET   "\x1b[0m"

extern void* chacha20_Full(void* message, void* out_message, int length);


// Function to search for a pattern with wildcards (0x00 = any byte)
int search_pattern(const unsigned char* buffer, size_t buffer_size, 
                  const unsigned char* pattern, const unsigned char* mask, 
                  size_t pattern_size, size_t start_index) {
    for (size_t i = start_index; i <= buffer_size - pattern_size; i++) {
        int found = 1;
        for (size_t j = 0; j < pattern_size; j++) {
            // If mask is 0xFF, we require exact match
            // If mask is 0x00, any byte is acceptable
            if (mask[j] == 0xFF && buffer[i + j] != pattern[j]) {
                found = 0;
                break;
            }
        }
        if (found) {
            return (int)i;
        }
    }
    return -1;
}

int obufcating_buffer(char *buffer, int fileSize){
    // First pattern: 4C 8D 15 00 00 00 00 41 BD 00 00 00 00 E8 00 00 00 00
    unsigned char pattern1[] = {
        0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, 
        0x41, 0xBD, 0x00, 0x00, 0x00, 0x00, 
        0xE8, 0x00, 0x00, 0x00, 0x00
    };
    
    unsigned char mask1[] = {
        0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0x00, 0x00, 0x00, 0x00
    };
    size_t pattern1_size = sizeof(pattern1);

    // Second pattern: 4C 8D 15 00 00 00 00 49 83 EA 00 41 BD 00 00 00 00 E8 00 00 00 00
    unsigned char pattern2[] = {
        0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,
        0x49, 0x83, 0xEA, 0x00,
        0x41, 0xBD, 0x00, 0x00, 0x00, 0x00,
        0xE8, 0x00, 0x00, 0x00, 0x00
    };
    
    unsigned char mask2[] = {
        0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0x00, 0x00, 0x00, 0x00
    };
    size_t pattern2_size = sizeof(pattern2);

    int scaning_pos = 0;

    while(TRUE){

            // Search for first pattern
        int pos1 = search_pattern(buffer, fileSize, pattern1, mask1, pattern1_size, scaning_pos);
        if (pos1 == -1) {
            printf(COLOR_GOLDEN_YELLOW "Warning: Not pattern1 Found!\n" COLOR_RESET);
            return 1;
        }
        // Search for second pattern after first pattern
        int pos2 = search_pattern(buffer, fileSize, pattern2, mask2, pattern2_size, pos1 + pattern1_size);
        if (pos2 == -1) {
            printf(COLOR_RED "Error: Not pattern2 Found!\n" COLOR_RESET);
            return -1;
        }
        scaning_pos = pos2 + pattern1_size;

        // Calculate byte count between patterns
        int byte_count = pos2 - (pos1 + pattern1_size);

        chacha20_Full(&buffer[pos1 + pattern1_size], &buffer[pos1 + pattern1_size], byte_count);

        printf(COLOR_GREEN "* %d Bytes was De/Obufcated\n" COLOR_RESET, byte_count);

        // Check bounds before each memcpy
        if (pos1 + 9 + sizeof(DWORD) > fileSize) {
            fprintf(stderr, COLOR_RED "Error: pos1+9 out of bounds\n" COLOR_RESET);
            return -1;
        }
        if (pos2 + 10 + sizeof(BYTE) > fileSize) {
            fprintf(stderr, COLOR_RED "Error: pos2+10 out of bounds\n" COLOR_RESET);
            return -1;
        }
        if (pos2 + 13 + sizeof(DWORD) > fileSize) {
            fprintf(stderr, COLOR_RED "Error: pos2+13 out of bounds\n" COLOR_RESET);
            return -1;
        }

        //coping bytes into buffer
        memcpy(&buffer[pos1+9], &byte_count, sizeof(DWORD));
        memcpy(&buffer[pos2+10], &byte_count, sizeof(BYTE));
        memcpy(&buffer[pos2+13], &byte_count, sizeof(DWORD));
    }

}

int main(int argc, char* argv[]) {

    if (argc != 2) {
        printf(COLOR_RED "Usage: %s <filename>\n" COLOR_RESET, argv[0]);
        return 1;
    }

    printf(COLOR_GOLDEN_YELLOW "Warning: This Tool can be used for obufcation and unobufcation too if you accidently run two time it in file was UnObufcated\n" COLOR_RESET);

    const char* filename = argv[1];

    FILE* file = fopen(argv[1], "rb+");
    if (!file) {
        printf(COLOR_RED "Error: Cannot open file %s\n" COLOR_RESET, argv[1]);
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        printf(COLOR_RED "Error: Memory allocation failed\n" COLOR_RESET);
        fclose(file);
        return 1;
    }

    if (fread(buffer, 1, fileSize, file) != fileSize) {
        printf(COLOR_RED "Error: Cannot read file\n" COLOR_RESET);
        free(buffer);
        fclose(file);
        return 1;
    }

    printf("File size: %lu bytes\n", fileSize);

    //obucating
    printf("\nStarting De/Obufcating ...\n");
    int obfResult = obufcating_buffer(buffer, fileSize);

    if(obfResult == -1){
        printf(COLOR_RED "Error: This can be huge mistake you put obufcation but you did not put end obufcation\n" COLOR_RESET);
        free(buffer);
        fclose(file);
        return 1;
    }
    printf("Finished De/Obufcatiob\n\n");

    //point to file begin
    rewind(file);

    if (fwrite(buffer, 1, fileSize, file) != fileSize) {
        printf(COLOR_RED "Error: Cannot read file\n" COLOR_RESET);
        free(buffer);
        fclose(file);
        return 1;
    }

    fclose(file);


    free(buffer);
    return 0;
}