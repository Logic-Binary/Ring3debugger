#include<Windows.h>
#include<stdio.h>
#include<winternl.h>
#pragma comment(lib,"ntdll.lib")
#define PATH L"S:\\�쳣�����\\dbg1.0 - ���� (2)\\Debug\\DebuggerDll.dll"

BOOL NQIP_Flag() {
	BOOL flag = FALSE;
	NtQueryInformationProcess(
		GetCurrentProcess(),
		(PROCESSINFOCLASS)0x1F,
		&flag,
		sizeof(flag),
		NULL
	);
	return flag ? FALSE : TRUE;
}

int main() {

	LoadLibrary(L"DebuggerDll.dll");


	printf("�״μ��\n");
	if (IsDebuggerPresent()) {
		printf("������\n");
	}
	else {
		printf("��ȫ\n");
	}
	printf("�ڶ��μ��\n");
	BOOL is_check = FALSE;
	is_check = NQIP_Flag();
	if (is_check) {
		printf("���Ǳ�����\n");
	}
	else {
		printf("ȷ�ϰ�ȫ\n");
	}

	system("pause");
	return 0;
}