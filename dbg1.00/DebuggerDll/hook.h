#pragma once
#include<winternl.h>
#pragma comment(lib,"ntdll.lib")

extern HMODULE g_Module;

void initHook();

void onHook();

void closeHook();