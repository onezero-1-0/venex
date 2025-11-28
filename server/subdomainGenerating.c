#include <wchar.h>
#include <windows.h>
#include <stdio.h>

void generate_subdomains_by_date(wchar_t buffer[][32], int count) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    // Seed = YYYYMMDD + secret salt
    DWORD seed = (st.wYear * 10000) + (st.wMonth * 100) + st.wDay;

    // Simple but good enough LCG instead of srand/rand
    for(int i = 0; i < count; i++) {
        seed = 1664525 * seed + 1013904223;        // constants from Numerical Recipes
        DWORD r = (seed >> 16) & 0x7FFF;

        wchar_t subdomain[12] = {0};

        for(int j = 0; j < 12; j++) {
            seed = 1664525 * seed + 1013904223;
            r = (seed >> 16) & 0x7FFF;
            r = r % 62;
            if (r < 26)
                subdomain[j] = L'A' + r;        // uppercase
            else if (r < 52)
                subdomain[j] = L'a' + (r-26);   // lowercase
            else
                subdomain[j] = L'0' + (r-52);   // digits
        }

        // Copy subdomain into buffer[i]
        memcpy(buffer[i], subdomain, 24);
        memcpy(buffer[i] + 12, L".duckdns.org", 24);

        // Null terminate
        buffer[i][24] = L'\0'; // total 24 chars: 12+12
    }
}

int main(){
    wchar_t subdomain[10][32];
    generate_subdomains_by_date(subdomain, 10);

    for(int i = 0; i < 10; i++){
        wprintf(L"%ls\n", subdomain[i]);
    }

}

