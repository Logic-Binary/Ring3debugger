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

	//����ƫ��
    DWORD dwOffset = 
        (DWORD)MyNtQueryInformationProcess - a -5;
        // (DWORD)MyNtQueryInformationProcess - (DWORD)0x77bf4cf0 -5;
    //����ƫ��
    *(PDWORD)offset = dwOffset;
    //��newOpcode��ֵ
    newOpcode[0] = 0xE9;
    for (int i = 1; i < 5; i++) {
        newOpcode[i] = offset[i - 1];
    }

    //���ɵ�ַ��ǰ5��opcode����
    for (int i = 0; i < 5; i++) {
        oldOpcode[i] = ((PCHAR)a)[i];
    }
    //memcpy_s(oldOpcode,5,NtQueryInformationProcess,5);
}

void onHook() {
    //����ҳ������
    DWORD oldProtect = 0;
    DWORD procAddress = a;
    VirtualProtect((LPVOID)a, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    //��ԭ����ַ�ϵ�opcode���ΪE9 offset
    memcpy_s((LPVOID)a, 5, newOpcode, 5);
    //��ҳ�����ԸĻ�ȥ
    VirtualProtect((LPVOID)a, 5, oldProtect, &oldProtect);
}

void closeHook() {
    //����ҳ������
    DWORD oldProtect = 0;
    VirtualProtect((LPVOID)a, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    //����ַ��ԭ
    memcpy_s((LPVOID)a, 5, oldOpcode, 5);
    //��ҳ�����ԸĻ�ȥ
    VirtualProtect((LPVOID)a, 5, oldProtect, &oldProtect);
}