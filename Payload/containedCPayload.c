#include <windows.h>
#include <winternl.h>
#include <intrin.h>

typedef HMODULE(WINAPI *LoadLibraryA_t)(LPCSTR);
typedef FARPROC(WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
typedef int(WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

FARPROC GetProcAddressF(HMODULE hModule, const char *procName)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE *)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hModule +
                                                                  ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD *)((BYTE *)hModule + exportDir->AddressOfNames);
    WORD *ordinals = (WORD *)((BYTE *)hModule + exportDir->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)((BYTE *)hModule + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        char *name = (char *)((BYTE *)hModule + names[i]);

        int match = 1;
        const char *p1 = name;
        const char *p2 = procName;
        while (*p1 && *p2)
        {
            if (*p1 != *p2)
            {
                match = 0;
                break;
            }
            p1++;
            p2++;
        }
        if (match && !*p1 && !*p2)
        {
            return (FARPROC)((BYTE *)hModule + functions[ordinals[i]]);
        }
    }
    return NULL;
}

void mainCRTStartup()
{
    PPEB peb = (PPEB)__readgsqword(0x60);

    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY listHead = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY listEntry = listHead->Flink;

    listEntry = listEntry->Flink; // Skip Exe
    listEntry = listEntry->Flink; // Skip Ntdll

    HMODULE kernel32Base = *(HMODULE *)((BYTE *)listEntry + 0x20);

    // Define strings on stack. We cannot use char* s = "LoadLibraryA" because that puts the string in .rdata (relocation not possible)
    char s_LoadLib[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0};
    char s_GetProc[] = {'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0};
    char s_User32[] = {'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0};
    char s_MsgBox[] = {'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0};
    char s_Title[] = {'P', 'a', 'y', 'l', 'o', 'a', 'd', 0};

    GetProcAddress_t getProcAddressFunc = (GetProcAddress_t)GetProcAddressF(kernel32Base, s_GetProc);
    LoadLibraryA_t loadLibraryAFunc = (LoadLibraryA_t)GetProcAddressF(kernel32Base, s_LoadLib);
    HMODULE user32Base = loadLibraryAFunc(s_User32);

    MessageBoxA_t messageBoxFunc = (MessageBoxA_t)GetProcAddressF(user32Base, s_MsgBox);

    messageBoxFunc(NULL, s_Title, s_Title, 0);

    // loop as returning to no where might cause a crash.
    while (1)
    {
    }
}