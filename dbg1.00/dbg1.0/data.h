#pragma once
#include "capstone/include/capstone.h"
#pragma comment(lib,"XEDParse.lib")
#pragma comment(lib,"ntdll.lib")
#include<DbgHelp.h>
#pragma comment(lib,"Dbghelp.lib")

//#include "S:\\异常与调试\\dbg1.0\\dbg1.0\\capstone\\include\\capstone.h"
#ifdef _WIN64 
#pragma comment(lib, "capstone/lib/capstone_x64.lib")
#else
#pragma comment(lib,"capstone\\lib\\capstone_x86.lib")
#endif
#define PATH  L"..\\DeBug\\helloworld.exe"
#define PATH2 L"..\\DeBug\\test1.exe"
#define PATH3 L"S:\\异常与调试\\调试目标\\DemoExe.exe"
#define PATH4 L"..\\Debug\\DebuggerDll.dll"

typedef void(*fun)();

typedef struct _EFLAGS
{
	unsigned CF : 1;       //进位或错位
	unsigned Reserve1 : 1;
	unsigned PF : 1;       //计算结果低位包含偶数个1时，此标志为1
	unsigned Reserve2 : 1;
	unsigned AF : 1;       //辅助进位标志，当位3处有进位或借位标志时该标志为1
	unsigned Reserve3 : 1;
	unsigned ZF : 1;       //计算结果为0时，此标志为1
	unsigned SF : 1;       //符号标志，计算结果为负时该标志为1
	unsigned TF : 1;       //陷阱标志，此标志为1时，CPU每次仅会执行1条命令
	unsigned IF : 1;       //中断标志，为0时禁止响应（屏蔽中断），为1时恢复
	unsigned DF : 1;       //方向标志
	unsigned OF : 1;       //溢出标志，计算结果超出机器所表达范围时为1,否则为0
	unsigned IOPL : 2;       //用于标明当前任务的I/O特权级
	unsigned NT : 1;       //任务嵌套标志
	unsigned Reserve4 : 1;
	unsigned RF : 1;       //调试异常相应控制标志位，为1禁止响应指令断点异常
	unsigned VM : 1;       //为1时启用虚拟8086模式
	unsigned AC : 1;       //内存对齐检查标志
	unsigned VIF : 1;       //虚拟中断标志
	unsigned VIP : 1;       //虚拟中断标志
	unsigned ID : 1;       //CPUID检查标志
	unsigned Reserve5 : 10;
}EFLAGS, * PEFLAGS;

// DR7寄存器结构体
typedef struct _DBG_REG7 {
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// 保留的无效空间
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} R7, * PR7;

//DR6寄存器结构体
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
	//软件断点地址容器
	DWORD BreakPoint;
	//存放保存的字节
	CHAR OldOpcode;
	//指令长度
	USHORT Lenth;
	//条件
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
