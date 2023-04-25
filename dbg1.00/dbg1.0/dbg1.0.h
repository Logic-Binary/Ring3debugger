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
	//������֮DLLע��
	void hookNtQueryInformationProcess();
	//����Plug�ļ���
	void traversalFile();
	//API��ַ��ѯ
	SIZE_T CheckApiAddress(const char* pszName);
	~DBG();


public:
	//�����¼��ṹ��
	DEBUG_EVENT m_stcDeEvent;
	//���������ṹ��
	CONTEXT m_stcContext;
	//�ظ���ϵͳ����3
	DWORD m_dwRetCode;
	//�߳̾��
	HANDLE m_hThread;
	//���̾��
	HANDLE m_hProcess;
	//OEP
	DWORD m_dwOEP;
	//��һ��ϵͳ�׳��쳣
	CHAR m_FirstException;
	//EFLAGE
	PEFLAGS m_pEflags;
	//�����ϵ���ʱ��ַ
	DWORD m_dwSinglePoint;
	//�����ϵ��ָ���
	DWORD m_dwSinglePointLenth;
	//����ϵ�ṹ��
	vector<BREAKPOINTINFOMATION> m_vecBreakPoint2;
	//Ӳ���ϵ�ṹ��
	HARDBREAKPOINT m_aHardBreakPoint[4];
	//�ɵ��ڴ汣��ҳ������
	DWORD dwOldProtect;
	//�ڴ�ϵ�ṹ��
	MEMORYPOINTINFOMATION m_stcMemPointInf;
	//������ػ�ַ
	DWORD m_dwPID;
	//�ļ����
	HANDLE m_hFile;
	//����ָ������
	vector<fun> m_vecFun;
};


