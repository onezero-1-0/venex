#include "WinGost.h"

void PrintModule(PFUNCTION_TABLE ft) {
    ft->Kernel32.WriteConsoleA(
        ft->Kernel32.GetStdHandle(-11), // STD_OUTPUT_HANDLE
        "Module executed successfully!\n",
        30,
        NULL,
        NULL
    );
    return;
}