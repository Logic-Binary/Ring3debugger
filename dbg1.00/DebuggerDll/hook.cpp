#include"pch.h"
#include"hook.h"

CHAR oldOpcode[5] = {};
CHAR newOpcode[5] = {};
CHAR offset[4] = {};

__kernel_entry NTSTATUS NTAPI MyNtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
) {
    closeHook();
    if (ProcessInformationClass == 0x1F) {
        *(int*)ProcessInformation = TRUE;
        onHook();
        return TRUE;
    }

    NTSTATUS retCode = 0;
    retCode = NtQueryInformationProcess(
        ProcessHandle,
        ProcessInformationClass,
        ProcessInformation,
        ProcessInformationLength,
        ReturnLength OPTIONAL);
    onHook();  
    return retCode; 
}

DWORD a = 0;
void initHook() {
    HMODULE h = LoadLibrary(L"ntdll.dll");
    a = (DWORD)GetProcAddress(h,"NtQueryInformationProcess");

	//计算偏移
    DWORD dwOffset = 
        (DWORD)MyNtQueryInformationProcess - a -5;
        // (DWORD)MyNtQueryInformationProcess - (DWORD)0x77bf4cf0 -5;
    //保存偏移
    *(PDWORD)offset = dwOffset;
    //给newOpcode赋值
    newOpcode[0] = 0xE9;
    for (int i = 1; i < 5; i++) {
        newOpcode[i] = offset[i - 1];
    }

    //将旧地址的前5个opcode保存
    for (int i = 0; i < 5; i++) {
        oldOpcode[i] = ((PCHAR)a)[i];
    }
    //memcpy_s(oldOpcode,5,NtQueryInformationProcess,5);
}

void onHook() {
    //更改页的属性
    DWORD oldProtect = 0;
    DWORD procAddress = a;
    VirtualProtect((LPVOID)a, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    //将原来地址上的opcode码改为E9 offset
    memcpy_s((LPVOID)a, 5, newOpcode, 5);
    //将页的属性改回去
    VirtualProtect((LPVOID)a, 5, oldProtect, &oldProtect);
}

void closeHook() {
    //更改页的属性
    DWORD oldProtect = 0;
    VirtualProtect((LPVOID)a, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    //将地址还原
    memcpy_s((LPVOID)a, 5, oldOpcode, 5);
    //将页的属性改回去
    VirtualProtect((LPVOID)a, 5, oldProtect, &oldProtect);
}