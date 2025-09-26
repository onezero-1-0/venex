#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

// External function provided
extern void* chacha20_Full(void* message, void* buffer, uint64_t length);

// Convert string of hex (like "0x32, 0x2D") to raw bytes
size_t hex_to_bytes(const char* hexstr, unsigned char* out) {
    size_t count = 0;
    const char* p = hexstr;

    while (*p) {
        while (*p && !isxdigit(*p)) p++; // skip non-hex
        if (!*p) break;

        unsigned int val;
        if (sscanf(p, "%x", &val) == 1) {
            out[count++] = (unsigned char)val;
        }

        while (*p && (isxdigit(*p) || *p=='x' || *p=='X')) p++; 
        while (*p && (*p==',' || isspace(*p))) p++; 
    }
    return count;
}

// Print buffer as hex
void print_hex(const unsigned char* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("0x%02X", buf[i]);
        if (i < len-1) printf(", ");
    }
    printf("\n");
}

int main() {
    char choice[10];
    printf("Input type (string/hex): ");
    scanf("%9s", choice);
    getchar(); // clear newline

    unsigned char input[1024];
    unsigned char output[1024];
    size_t length = 0;

    if (strcasecmp(choice, "string") == 0) {
        printf("Enter string: ");
        fgets((char*)input, sizeof(input), stdin);
        length = strlen((char*)input);

        if (input[length-1] == '\n') {
            input[length-1] = '\0';
            length--;
        }

        chacha20_Full(input, output, length);

        printf("Encrypted/Decrypted (hex): ");
        print_hex(output, length);

    } else if (strcasecmp(choice, "hex") == 0) {
        char hexline[2048];
        printf("Enter hex values (e.g., 0x32, 0x2D, 0x62): ");
        fgets(hexline, sizeof(hexline), stdin);

        length = hex_to_bytes(hexline, input);

        chacha20_Full(input, output, length);

        printf("\nEncrypted/Decrypted (string): ");
        for (size_t i = 0; i < length; i++) {
            printf("%c", isprint(output[i]) ? output[i] : '.');
        }
        printf("\n");

        printf("\nEncrypted/Decrypted (hex): ");
        print_hex(output, length);

    } else {
        printf("Invalid choice. Use 'string' or 'hex'.\n");
    }

    return 0;
}
