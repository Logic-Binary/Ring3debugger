#pragma once
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <iostream>
#include <tlhelp32.h>
#include <conio.h>
#include <winternl.h>
#include "data.h"
#include "XEDParse.h"
using std::vector;
using std::string;
using std::cin;

class DBG {
public:
	DBG();
	BOOL createOpen(const TCHAR* pszFile);
	BOOL addOpen(DWORD dwPid);
	void debugEnentLoop();
	void getContext();
	void printContext();
	BOOL getDisasmAsm(LPVOID address,DWORD line);
	BOOL setBreakPoint_int3(LPVOID address);
	BOOL removeBreakPoint_int3(LPVOID address);
	BOOL handleException(EXCEPTION_DEBUG_INFO dbgInfo);
	BOOL setEflagTF1(DWORD exceptionType);
	void handleInt3Point(DWORD address);
	void handleSingleStep(DWORD dwExceptionocde, DWORD address);
	void handleMemoryPoint(DWORD address, DWORD type);
	BOOL handleInPut();
	void setHardBreakPoint(BYTE byType,BYTE byLen,DWORD dwAddress);
	void ResumeDR7();
	BOOL siftExpection(DWORD dwAddress,DWORD dwVirtualAddress,DWORD dwType);
	USHORT getDisasmAsmLenth(LPVOID address);
	void setMemoryPoint(DWORD byType, DWORD byLen, DWORD dwAddress);
	void changeRegInfomation(string strReg,DWORD dwValue);
	void checkModuleInfomation(DWORD dwPID);
	void modifyDisasm();
	void checkESP();
	void modifyData();
	void lookData();
	BOOL OpposeToOpposeDebug();
	void analyzeTable0();
	void analyzeTable1();
	DWORD RVA2FOA(PCHAR file,DWORD RVA);
	//反调试之DLL注入
	void hookNtQueryInformationProcess();
	//遍历Plug文件夹
	void traversalFile();
	//API地址查询
	SIZE_T CheckApiAddress(const char* pszName);
	~DBG();


public:
	//调试事件结构体
	DEBUG_EVENT m_stcDeEvent;
	//环境变量结构体
	CONTEXT m_stcContext;
	//回复子系统参数3
	DWORD m_dwRetCode;
	//线程句柄
	HANDLE m_hThread;
	//进程句柄
	HANDLE m_hProcess;
	//OEP
	DWORD m_dwOEP;
	//第一次系统抛出异常
	CHAR m_FirstException;
	//EFLAGE
	PEFLAGS m_pEflags;
	//单步断点临时地址
	DWORD m_dwSinglePoint;
	//单步断点的指令长度
	DWORD m_dwSinglePointLenth;
	//软件断点结构体
	vector<BREAKPOINTINFOMATION> m_vecBreakPoint2;
	//硬件断点结构体
	HARDBREAKPOINT m_aHardBreakPoint[4];
	//旧的内存保护页面属性
	DWORD dwOldProtect;
	//内存断点结构体
	MEMORYPOINTINFOMATION m_stcMemPointInf;
	//程序加载基址
	DWORD m_dwPID;
	//文件句柄
	HANDLE m_hFile;
	//函数指针容器
	vector<fun> m_vecFun;
};


