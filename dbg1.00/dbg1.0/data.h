#pragma once
#include "capstone/include/capstone.h"
#pragma comment(lib,"XEDParse.lib")
#pragma comment(lib,"ntdll.lib")
#include<DbgHelp.h>
#pragma comment(lib,"Dbghelp.lib")

//#include "S:\\�쳣�����\\dbg1.0\\dbg1.0\\capstone\\include\\capstone.h"
#ifdef _WIN64 
#pragma comment(lib, "capstone/lib/capstone_x64.lib")
#else
#pragma comment(lib,"capstone\\lib\\capstone_x86.lib")
#endif
#define PATH  L"..\\DeBug\\helloworld.exe"
#define PATH2 L"..\\DeBug\\test1.exe"
#define PATH3 L"S:\\�쳣�����\\����Ŀ��\\DemoExe.exe"
#define PATH4 L"..\\Debug\\DebuggerDll.dll"

typedef void(*fun)();

typedef struct _EFLAGS
{
	unsigned CF : 1;       //��λ���λ
	unsigned Reserve1 : 1;
	unsigned PF : 1;       //��������λ����ż����1ʱ���˱�־Ϊ1
	unsigned Reserve2 : 1;
	unsigned AF : 1;       //������λ��־����λ3���н�λ���λ��־ʱ�ñ�־Ϊ1
	unsigned Reserve3 : 1;
	unsigned ZF : 1;       //������Ϊ0ʱ���˱�־Ϊ1
	unsigned SF : 1;       //���ű�־��������Ϊ��ʱ�ñ�־Ϊ1
	unsigned TF : 1;       //�����־���˱�־Ϊ1ʱ��CPUÿ�ν���ִ��1������
	unsigned IF : 1;       //�жϱ�־��Ϊ0ʱ��ֹ��Ӧ�������жϣ���Ϊ1ʱ�ָ�
	unsigned DF : 1;       //�����־
	unsigned OF : 1;       //�����־��������������������ﷶΧʱΪ1,����Ϊ0
	unsigned IOPL : 2;       //���ڱ�����ǰ�����I/O��Ȩ��
	unsigned NT : 1;       //����Ƕ�ױ�־
	unsigned Reserve4 : 1;
	unsigned RF : 1;       //�����쳣��Ӧ���Ʊ�־λ��Ϊ1��ֹ��Ӧָ��ϵ��쳣
	unsigned VM : 1;       //Ϊ1ʱ��������8086ģʽ
	unsigned AC : 1;       //�ڴ�������־
	unsigned VIF : 1;       //�����жϱ�־
	unsigned VIP : 1;       //�����жϱ�־
	unsigned ID : 1;       //CPUID����־
	unsigned Reserve5 : 10;
}EFLAGS, * PEFLAGS;

// DR7�Ĵ����ṹ��
typedef struct _DBG_REG7 {
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// ��������Ч�ռ�
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} R7, * PR7;

//DR6�Ĵ����ṹ��
typedef struct _DBG_REG6 {
	unsigned B0 : 1; unsigned B1 : 1;
	unsigned B2 : 1; unsigned B3 : 1;
	unsigned Reserve1 : 8;
	unsigned BB : 4;
	unsigned Reserve2 : 16;
}R6, * PR6;

typedef struct _HARDBREAKPOINT {
	DWORD address;
	BYTE byType;
	BYTE byLen;
	BOOL isUse;
}HARDBREAKPOINT, * PHARDBREAKPOINT;

typedef struct _BREAKPOINTINFOMATION
{
	//����ϵ��ַ����
	DWORD BreakPoint;
	//��ű�����ֽ�
	CHAR OldOpcode;
	//ָ���
	USHORT Lenth;
	//����
	BOOL is_use;
	DWORD EAX;


}BREAKPOINTINFOMATION, * PBREAKPOINTINFOMATION;

typedef struct _MEMORYPOINTINFOMATION
{
	DWORD Address;
	DWORD byType;
	DWORD byLen;
	DWORD OldProtect;
	BOOL isUse;
	DWORD Protected;
}MEMORYPOINTINFOMATION, * PMEMORYPOINTINFOMATION;
