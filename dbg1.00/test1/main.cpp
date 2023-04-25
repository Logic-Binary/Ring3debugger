#include<Windows.h>
#include<stdio.h>
#include<winternl.h>
#pragma comment(lib,"ntdll.lib")
#define PATH L"S:\\异常与调试\\dbg1.0 - 副本 (2)\\Debug\\DebuggerDll.dll"

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


	printf("首次检查\n");
	if (IsDebuggerPresent()) {
		printf("被调试\n");
	}
	else {
		printf("安全\n");
	}
	printf("第二次检查\n");
	BOOL is_check = FALSE;
	is_check = NQIP_Flag();
	if (is_check) {
		printf("还是被调试\n");
	}
	else {
		printf("确认安全\n");
	}

	system("pause");
	return 0;
}