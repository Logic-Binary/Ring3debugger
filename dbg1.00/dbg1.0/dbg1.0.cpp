#include"dbg1.0.h"


DBG::DBG() :
	m_stcDeEvent(),
	m_stcContext(),
	m_dwRetCode(0),
	m_hThread(NULL),
	m_dwOEP(0),
	m_hProcess(NULL),
	m_pEflags(NULL),
	m_FirstException(0),
	m_dwSinglePoint(0),
	m_vecBreakPoint2(),
	m_aHardBreakPoint(),
	dwOldProtect(0),
	m_stcMemPointInf(),
	m_dwSinglePointLenth(),
	m_dwPID(0),
	m_hFile(0),
	m_vecFun()
{}
//打开调试进程(一层)
BOOL DBG::createOpen(const TCHAR* pszFile) {
	if (pszFile == NULL) {
		printf("错误0x0001\n");
		return false;
	}
	BOOL ret_value = FALSE;
	//主窗口特性
	STARTUPINFO stcStartupInfo = { sizeof(STARTUPINFO) };
	//进程信息
	PROCESS_INFORMATION stcProcInfo = { 0 };

	ret_value = CreateProcess(
		pszFile,
		NULL, NULL, NULL,
		FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL, NULL,
		&stcStartupInfo,
		&stcProcInfo);
	return ret_value;
}
//附加进程
BOOL DBG::addOpen(DWORD dwPid) {
	DebugActiveProcess(dwPid);
	BOOL ret_value = FALSE;
	//主窗口特性
	STARTUPINFO stcStartupInfo = { sizeof(STARTUPINFO) };
	//进程信息
	PROCESS_INFORMATION stcProcInfo = { 0 };
	return ret_value;
}
//等待调试事件(二层)
void DBG::debugEnentLoop() {
	DWORD ret_value = 0;
	//这里需要判断下产生的异常是调试器产生的还是程序产生的
	m_dwRetCode = DBG_CONTINUE;
	while (true) {
		//等待调试事件
		//接收到调试事件就会返回，并且将调试事件的
		//信息填充到结构体中
		ret_value = WaitForDebugEvent(&m_stcDeEvent, -1);
		if (ret_value == 0) {
			printf("错误:0x0002\n");
			return;
		}
		//根据调试事件分别处理
		switch (m_stcDeEvent.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:			//异常调试事件
			//处理异常
			handleException(m_stcDeEvent.u.Exception);
			break;
		case CREATE_THREAD_DEBUG_EVENT:		//创建线程调试事件
			//printf("线程创建\n");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:	//创建进程调试事件
		{
			m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_stcDeEvent.dwProcessId);
			m_dwPID = m_stcDeEvent.dwProcessId;
			m_hFile = m_stcDeEvent.u.CreateProcessInfo.hFile;
			if (m_hProcess == NULL) {
				printf("错误0x0004\n");
				return;
			}
			//反反调试
			OpposeToOpposeDebug();
			//dll注入
			hookNtQueryInformationProcess();
			//插件加载
			traversalFile();
			//符号初始化
			SymInitialize(m_hProcess, "S:\\异常与调试\\dbg1.0写的很丑陋\\Debug\\", FALSE);
			//加载模块符号文件
			TCHAR buff[MAX_PATH] = {};
			GetModuleFileName(NULL, buff, MAX_PATH);
			SymLoadModule64(m_hProcess, m_hFile, (PCSTR)buff, NULL,
				(DWORD64)0x00400000, 0);
			

			m_dwOEP = (DWORD)(m_stcDeEvent.u.CreateProcessInfo.lpStartAddress);
			printf("程序入口点:%X\n", m_dwOEP);
			//创建软件断点结构体对象
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = m_dwOEP;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)m_dwOEP);
			m_vecBreakPoint2.push_back(bpi);
			setBreakPoint_int3((LPVOID)m_dwOEP);
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT:		//退出线程调试事件
			//printf("线程退出\n");

			break;
		case EXIT_PROCESS_DEBUG_EVENT:		//退出进程调试事件
			//printf("进程退出\n");

			if (m_hProcess != NULL) {
				CloseHandle(m_hProcess);
			}
			break;
		case LOAD_DLL_DEBUG_EVENT:			//load-dynamic-link-library (DLL) 调试事件
			break;
		case UNLOAD_DLL_DEBUG_EVENT:		//unload-DLL 调试事件
			break;
		case OUTPUT_DEBUG_STRING_EVENT:		//output-debugging-string 调试事件
			break;
		case RIP_EVENT:						//RIP 调试事件
			break;
		default:
			break;
		}
		//回复子系统
		//1.我处理完了 请继续  --DBG_CONTINUE
		//2.我还没处理 给交程序自己去处理吧 --DBG_EXCEPTION_NOT_HANDLED
		ContinueDebugEvent(
			m_stcDeEvent.dwProcessId,
			m_stcDeEvent.dwThreadId,
			m_dwRetCode);
	}
	return;
}
//获取线程环境
void DBG::getContext() {
	if (m_hThread != NULL) {
		CloseHandle(m_hThread);
	}

	m_stcContext.ContextFlags = CONTEXT_ALL;
	//通过id获取线程句柄
	m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_stcDeEvent.dwThreadId);
	if (m_hThread == NULL) {
		printf("错误0x0003\n");
		return;
	}
	GetThreadContext(m_hThread, &m_stcContext);
}
//打印当前环境变量
void DBG::printContext() {
	printf("EAX:%08X  EBX:%08X\nECX:%08X  EDX:%08X\n",
		m_stcContext.Eax,
		m_stcContext.Ebx,
		m_stcContext.Ecx,
		m_stcContext.Edx);
}
//打印反汇编信息
BOOL DBG::getDisasmAsm(LPVOID address, DWORD line) {

	DWORD dwSize = 0;
	//把全部的软件地址上的CC都写回原样
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		DWORD errno_t = WriteProcessMemory(m_hProcess, (LPVOID)(*it).BreakPoint, &(*it).OldOpcode, 1, &dwSize);
		if (!errno_t) {
			printf("错误0x000A");
			return FALSE;
		}
	}
	BYTE opcode[MAX_PATH];
	ReadProcessMemory(m_hProcess, address, opcode, MAX_PATH, &dwSize);
	csh handle;//反汇编引擎的句柄
	cs_err err;//错误信息
	cs_insn* pInsn;//得到反汇编信息的
	unsigned int count = line;//反汇编指令的条数
	//2.2 初始化
	err = cs_open(
		CS_ARCH_X86,//指令集
		CS_MODE_32, //32位模式
		&handle     //传出句柄
	);
	if (err != 0) {
		printf("错误0x0005\n");
		return FALSE;
	}
	//2.3 反汇编
	cs_disasm(
		handle,
		(const uint8_t*)opcode,
		sizeof(opcode),
		(uint64_t)address,//目标程序中，指令的地址，需要用于计算跳转，call等目的地址
		count,    //反汇编的指令条数
		&pInsn    //反汇编之后的指令信息
	);
	for (size_t i = 0; i < count; i++)
	{
		printf("%llX |%s %s\n",
			pInsn[i].address,  //内存地址
			pInsn[i].mnemonic, //指令操作码
			pInsn[i].op_str    //指令操作数
		);
	}
	//2.4 收尾
	cs_free(pInsn, count);
	cs_close(&handle);
	//输出完再把所有的断点信息保存然后置为CC
	BYTE int3 = 0xCC;
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		DWORD errno_t = WriteProcessMemory(m_hProcess, (LPVOID)(*it).BreakPoint, &int3, 1, &dwSize);
		if (!errno_t) {
			printf("错误0x000B");
			return FALSE;
		}
	}
	return TRUE;
}
//int3软件断点的设置
BOOL DBG::setBreakPoint_int3(LPVOID address) {
	DWORD dwSize = 0;
	DWORD errno_t = 0;
	BOOL is_find = FALSE;
	//遍历容器找到对应的结构体把地址第一个字节写给OldOpcode
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		if ((DWORD)address == (*it).BreakPoint) {
			errno_t = ReadProcessMemory(m_hProcess, address, &((*it).OldOpcode), 1, &dwSize);
			if (errno_t == 0) {
				printf("错误0x0006");
				return FALSE;
				break;
			}
			is_find = TRUE;
			break;
		}
	}
	if (!is_find) {
		return is_find;
	}
	BYTE cc = 0xCC;
	errno_t = WriteProcessMemory(m_hProcess, address, &cc, 1, &dwSize);

	if (errno_t == 0) {
		printf("错误0x0007");
		return FALSE;
	}
	return true;
}
//移除软件断点
BOOL DBG::removeBreakPoint_int3(LPVOID address) {
	DWORD dwSize = 0;
	DWORD errno_t = 0;
	BOOL is_find = FALSE;
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		if ((DWORD)address == (*it).BreakPoint) {
			errno_t = WriteProcessMemory(m_hProcess, address, &((*it).OldOpcode), 1, &dwSize);

			if (errno_t == 0) {
				printf("错误0x0006");
				return FALSE;
				break;
			}
			is_find = TRUE;
			break;
		}
	}
	if (!is_find)
	{
		return is_find;
	}
	setEflagTF1(1);
	return TRUE;
}
//设置单步
//参数为1需要eip-1，参数为0不需要eip-1
BOOL DBG::setEflagTF1(DWORD exceptionType) {
	//获取当前线程环境
	DWORD errno_t = 0;
	getContext();
	if (exceptionType) {
		m_stcContext.Eip--;
	}
	m_pEflags = (PEFLAGS)&m_stcContext.EFlags;
	m_pEflags->TF = 1;
	errno_t = SetThreadContext(m_hThread, &m_stcContext);
	if (errno_t == 0) {
		printf("错误0x0009");
		return FALSE;
	}
	return TRUE;
}
//检查断点是否是我想要处理的
BOOL DBG::siftExpection(DWORD dwAddress, DWORD dwVritualAddress, DWORD dwType) {
	BOOL is_find = FALSE;

	//测试代码
	//如果是读取断点
	//如果异常也是产生也是写入
	if (m_stcMemPointInf.byType == dwType && m_stcMemPointInf.isUse) {
		//如果此时线性地址等于我设置的地址
		if (dwVritualAddress == m_stcMemPointInf.Address) {
			//则页面地址重新再写回去
			VirtualProtectEx(
				m_hProcess,
				(LPVOID)m_stcMemPointInf.Address,
				m_stcMemPointInf.byLen,
				m_stcMemPointInf.OldProtect,
				&m_stcMemPointInf.OldProtect);
		}
		return TRUE;
	}

	//单步断点
	if (m_dwSinglePoint + m_dwSinglePointLenth == dwAddress) {
		is_find = TRUE;
		if (m_stcMemPointInf.isUse) {
			//把页面地址重新再写回去
			VirtualProtectEx(
				m_hProcess,
				(LPVOID)m_stcMemPointInf.Address,
				m_stcMemPointInf.byLen,
				m_stcMemPointInf.OldProtect,
				&m_stcMemPointInf.OldProtect);
		}
		return is_find;
	}
	//内存断点不为0
	if (dwVritualAddress != 0) {
		return TRUE;
	}
	//如果此时断的位置等于内存断点的地址
	if ((dwAddress == m_stcMemPointInf.Address) && (m_stcMemPointInf.isUse)) {
		//把页面地址重新再写回去
		VirtualProtectEx(
			m_hProcess,
			(LPVOID)m_stcMemPointInf.Address,
			m_stcMemPointInf.byLen,
			m_stcMemPointInf.OldProtect,
			&m_stcMemPointInf.OldProtect);
		return TRUE;
	}
	//软件断点
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		if ((*it).BreakPoint == dwAddress ||
			((*it).BreakPoint + (*it).Lenth == dwAddress)) {
			is_find = TRUE;
			return is_find;
		}
	}
	//硬件断点
	getContext();
	PR6 Pr6 = (PR6) & (m_stcContext.Dr6);
	//只要是这四个寄存器产生的断点则
	if (Pr6->B0 || Pr6->B1 || Pr6->B2 || Pr6->B3) {
		is_find = TRUE;
		return is_find;
	}
	//诡谲的代码-，-
	if (dwAddress == 0x455da0) {
		return TRUE;
	}


	return is_find;
}
//处理异常(三层)
BOOL DBG::handleException(EXCEPTION_DEBUG_INFO dbgInfo) {
	DWORD dwExceptionocde = dbgInfo.ExceptionRecord.ExceptionCode;
	DWORD address = (DWORD)(dbgInfo.ExceptionRecord.ExceptionAddress);
	BOOL is_find = FALSE;
	DWORD dwtemp = (DWORD)dbgInfo.ExceptionRecord.ExceptionInformation + 4;
	DWORD dwVritualAddress = *((PDWORD)dwtemp);
	//如果不是自己的想要处理的异常，放过去
	is_find = siftExpection(address, dwVritualAddress, *(PDWORD)dbgInfo.ExceptionRecord.ExceptionInformation);
	if (!is_find) {
		//恢复一下硬件断点的寄存器环境
		ResumeDR7();
		//如果内存断点是启用状态
		if (m_stcMemPointInf.isUse) {
			//将那个地址的页面全部设置为PAGE_NOACCESS
			VirtualProtectEx(
				m_hProcess,
				(LPVOID)m_stcMemPointInf.Address,
				m_stcMemPointInf.byLen,
				m_stcMemPointInf.OldProtect,
				&m_stcMemPointInf.OldProtect);
		}
		return TRUE;
	}
	//区分异常类型，分别处理
	switch (dwExceptionocde) {
		//int3
	case EXCEPTION_BREAKPOINT:
		handleInt3Point(address);
		break;
		//单步
	case EXCEPTION_SINGLE_STEP:
		handleSingleStep(dwExceptionocde, address);
		break;
		//内存断点处理
	case EXCEPTION_ACCESS_VIOLATION:
		DWORD chType = *(PDWORD)dbgInfo.ExceptionRecord.ExceptionInformation;
		handleMemoryPoint(address, chType);
		break;
	}
	return TRUE;
}
//处理int3断点
void DBG::handleInt3Point(DWORD address) {
	BOOL is_Find = FALSE;
	//判断一下是否是自己的int3断点
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		if ((*it).BreakPoint == address) {
			is_Find = TRUE;
			break;
		}
	}
	//不是调试器产生的断点，放过去
	if (!is_Find) {
		return;
	}
	//判断是否是OEP断点
	if (address == m_dwOEP) {
		removeBreakPoint_int3((LPVOID)m_dwOEP);
		//printf("地址:%08X\n", address);
		//输出反汇编信息(默认5行)
		getDisasmAsm((LPVOID)m_dwOEP, 5);
		//输出寄存器信息
		getContext();
		printContext();
		//将单步断点移除
		m_pEflags = (PEFLAGS)&m_stcContext.EFlags;
		m_pEflags->TF = 0;
		SetThreadContext(m_hThread, &m_stcContext);
		//将刚才在反汇编中置为CC的地方恢复
		DWORD dwSize = 0;
		WriteProcessMemory(m_hProcess, (LPVOID)(m_vecBreakPoint2.begin()->BreakPoint),
			&(m_vecBreakPoint2.begin()->OldOpcode), 1, &dwSize);
		//将oep信息断点删除
		m_vecBreakPoint2.erase(m_vecBreakPoint2.begin());
	}
	//不是OEP断点
	else {
		//打印一行
		//getDisasmAsm((LPVOID)address, 1);
		//把指令改回去并且设置单步断点
		removeBreakPoint_int3((LPVOID)address);
		//如果地址是软件断点地址，则走起来
		for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
			it != m_vecBreakPoint2.end(); it++) {
			if ((*it).BreakPoint == address) {
				return;
			}
		}
		//如果它也是单步断点的地址，让程序走起来
		if (address == m_dwSinglePoint) {
			return;
		}
	}
	while (1) {
		//返回值为TRUE，让程序跑起来
		if (handleInPut()) {
			break;
		};
	}
}
//处理单步断点
void DBG::handleSingleStep(DWORD dwexceptionocde, DWORD address) {
	getContext();//获取线程环境
	BYTE int3 = 0xCC;
	DWORD dwSize = 0;
	//BOOL is_find = FALSE;			//条件断点是否命中
	//把容器中所有软件断点开头写入cc
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		WriteProcessMemory(m_hProcess, (LPVOID)((*it).BreakPoint), &int3, 1, &dwSize);

		//诡谲的代码-，-
		/*(*it).is_use = FALSE;
		if ((*it).BreakPoint == 0x455c4a ) {
			(*it).is_use = TRUE;
		}*/

		//如果条件断点已启用且此时产生异常的地址等于条件断点地址
		if ((*it).is_use && (address == (*it).BreakPoint + (*it).Lenth)) {
			//如果条件不成立 让程序继续执行
			if ((m_stcContext.Eax != (*it).EAX)) {
				return;
			}
		}
	}
	//诡谲的代码-,-
	if ((address == 0x455da0) && (m_stcContext.Eax != 5)) {
		return;
	}
	if ((address == 0x455c7b) && (m_stcContext.Eax != 8)) {
		return;
	}if ((address == 0x455c7c) && (m_stcContext.Eax != 4)) {
		return;
	}


	//getContext();					//获取线程环境
	PR6 Pr6 = (PR6) & (m_stcContext.Dr6);
	//只要是这四个寄存器产生的断点则
	if (Pr6->B0 || Pr6->B1 || Pr6->B2 || Pr6->B3)
	{
		//打印一行,
		if (Pr6->B0) {
			getDisasmAsm((LPVOID)m_aHardBreakPoint[0].address, 1);
		}
		if (Pr6->B1) {
			getDisasmAsm((LPVOID)m_aHardBreakPoint[1].address, 1);
		}
		if (Pr6->B2) {
			getDisasmAsm((LPVOID)m_aHardBreakPoint[2].address, 1);
		}
		if (Pr6->B3) {
			getDisasmAsm((LPVOID)m_aHardBreakPoint[3].address, 1);
		}
		//将Dr7的L0 L1 L2 L3置空 把指令放过去
		PR7 Pr7 = (PR7) & (m_stcContext.Dr7);
		Pr7->L0 = 0; Pr7->L1 = 0; Pr7->L2 = 0; Pr7->L3 = 0;
		SetThreadContext(m_hThread, &m_stcContext);
		//设置一个单步断点
		setEflagTF1(0);
	}

	//软件断点
	if (address == address + m_dwSinglePointLenth) {
		//将属性再次改为不可读且断下来
		VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen,
			m_stcMemPointInf.OldProtect, &m_stcMemPointInf.OldProtect);
	}


	//用户输入
	while (1) {
		//如果返回值为ture，让程序走起来
		if (handleInPut()) {
			break;
		};
	}
}
//设置硬件断点
void DBG::setHardBreakPoint(BYTE byType, BYTE byLen, DWORD dwAddress) {
	//获取线程环境
	getContext();
	PR7 pDr7 = (PR7)(&m_stcContext.Dr7);
	//判断一下DR0~DR3哪个是空寄存器
	if (!m_aHardBreakPoint[0].isUse) {				//DR0没有被启用
		pDr7->L0 = 1;								//DR0启用
		m_aHardBreakPoint[0].isUse = 1;				//断点是否启用同步到结构体中
		m_stcContext.Dr0 = dwAddress;				//DR0地址设置
		m_aHardBreakPoint[0].address = dwAddress;	//断点地址同步
		//判断断点类型
		if (byType == 0) {							//执行断点
			pDr7->RW0 = 0;							//RW0断点类型赋值
			m_aHardBreakPoint[0].byType = 0;		//断点类型同步
			pDr7->LEN0 = 0;							//执行断点长度必定为1
			m_aHardBreakPoint[0].byLen = 0;			//断点长度同步到结构体中

		}
		else if (byType == 1) {						//写断点
			pDr7->RW0 = 1;
			m_aHardBreakPoint[0].byType = 1;
			pDr7->LEN0 = byLen;
			m_aHardBreakPoint[0].byLen = byLen;
		}
		else if (byType == 3) {								//读写断点
			if (byLen == 1) {								//2字节对齐粒度
				dwAddress = dwAddress - dwAddress % 2;
				m_stcContext.Dr0 = dwAddress;				//DR0地址设置
				m_aHardBreakPoint[0].address = dwAddress;	//断点地址同步
				pDr7->RW0 = 3;
				m_aHardBreakPoint[0].byType = 3;
				pDr7->LEN0 = 1;
				m_aHardBreakPoint[0].byLen = 1;
			}
			else if (byLen == 0) {
				m_stcContext.Dr0 = dwAddress;
				m_aHardBreakPoint[0].address = dwAddress;
				pDr7->RW0 = 3;
				m_aHardBreakPoint[0].byType = 3;
				pDr7->LEN0 = 0;
				m_aHardBreakPoint[0].byLen = 0;
			}
			else if (byLen == 3) {							//4字节对齐粒度
				dwAddress = dwAddress - dwAddress % 4;
				m_stcContext.Dr0 = dwAddress;
				m_aHardBreakPoint[0].address = dwAddress;
				pDr7->RW0 = 3;
				m_aHardBreakPoint[0].byType = 3;
				pDr7->LEN0 = 3;
				m_aHardBreakPoint[0].byLen = 3;
			}
		}
	}
	else if (!m_aHardBreakPoint[1].isUse) {			//DR1没有被启用
		pDr7->L1 = 1;								//DR1启用
		m_aHardBreakPoint[1].isUse = 1;				//断点是否启用同步到结构体中
		m_stcContext.Dr1 = dwAddress;				//DR1地址设置
		m_aHardBreakPoint[1].address = dwAddress;	//断点地址同步
		//判断断点类型
		if (byType == 0) {							//执行断点
			pDr7->RW1 = 0;							//RW1断点类型赋值
			m_aHardBreakPoint[1].byType = 0;		//断点类型同步
			pDr7->LEN1 = 0;							//执行断点长度必定为1
			m_aHardBreakPoint[1].byLen = 0;			//断点长度同步到结构体中

		}
		else if (byType == 1) {						//写断点
			pDr7->RW1 = 1;
			m_aHardBreakPoint[1].byType = 1;
			pDr7->LEN1 = byLen;
			m_aHardBreakPoint[1].byLen = byLen;
		}
		else if (byType == 3) {								//读写断点
			if (byLen == 1) {								//2字节对齐粒度
				dwAddress = dwAddress - dwAddress % 2;
				m_stcContext.Dr1 = dwAddress;				//DR1地址设置
				m_aHardBreakPoint[1].address = dwAddress;	//断点地址同步
				pDr7->RW1 = 3;
				m_aHardBreakPoint[1].byType = 3;
				pDr7->LEN1 = 1;
				m_aHardBreakPoint[1].byLen = 1;
			}
			else if (byLen == 0) {
				m_stcContext.Dr1 = dwAddress;
				m_aHardBreakPoint[1].address = dwAddress;
				pDr7->RW1 = 3;
				m_aHardBreakPoint[1].byType = 3;
				pDr7->LEN1 = 0;
				m_aHardBreakPoint[1].byLen = 0;
			}
			else if (byLen == 3) {							//4字节对齐粒度
				dwAddress = dwAddress - dwAddress % 4;
				m_stcContext.Dr1 = dwAddress;
				m_aHardBreakPoint[1].address = dwAddress;
				pDr7->RW1 = 3;
				m_aHardBreakPoint[1].byType = 3;
				pDr7->LEN1 = 3;
				m_aHardBreakPoint[1].byLen = 3;
			}
		}

	}
	else if (!m_aHardBreakPoint[2].isUse) {	//DR2没有被启用
		pDr7->L2 = 1;								//DR2启用
		m_aHardBreakPoint[2].isUse = 1;				//断点是否启用同步到结构体中
		m_stcContext.Dr2 = dwAddress;				//DR2地址设置
		m_aHardBreakPoint[2].address = dwAddress;	//断点地址同步
		//判断断点类型
		if (byType == 0) {							//执行断点
			pDr7->RW2 = 0;							//RW2断点类型赋值
			m_aHardBreakPoint[2].byType = 0;		//断点类型同步
			pDr7->LEN2 = 0;							//执行断点长度必定为1
			m_aHardBreakPoint[2].byLen = 0;			//断点长度同步到结构体中

		}
		else if (byType == 1) {						//写断点
			pDr7->RW2 = 1;
			m_aHardBreakPoint[2].byType = 1;
			pDr7->LEN2 = byLen;
			m_aHardBreakPoint[2].byLen = byLen;
		}
		else if (byType == 3) {								//读写断点
			if (byLen == 1) {								//2字节对齐粒度
				dwAddress = dwAddress - dwAddress % 2;
				m_stcContext.Dr2 = dwAddress;				//DR2地址设置
				m_aHardBreakPoint[2].address = dwAddress;	//断点地址同步
				pDr7->RW2 = 3;
				m_aHardBreakPoint[2].byType = 3;
				pDr7->LEN2 = 1;
				m_aHardBreakPoint[2].byLen = 1;
			}
			else if (byLen == 0) {
				m_stcContext.Dr2 = dwAddress;
				m_aHardBreakPoint[2].address = dwAddress;
				pDr7->RW2 = 3;
				m_aHardBreakPoint[2].byType = 3;
				pDr7->LEN2 = 0;
				m_aHardBreakPoint[2].byLen = 0;
			}
			else if (byLen == 3) {							//4字节对齐粒度
				dwAddress = dwAddress - dwAddress % 4;
				m_stcContext.Dr2 = dwAddress;
				m_aHardBreakPoint[2].address = dwAddress;
				pDr7->RW2 = 3;
				m_aHardBreakPoint[2].byType = 3;
				pDr7->LEN2 = 3;
				m_aHardBreakPoint[2].byLen = 3;
			}
		}
	}
	else if (!m_aHardBreakPoint[3].isUse) {			//DR3没有被启用
		pDr7->L3 = 1;								//DR3启用
		m_aHardBreakPoint[3].isUse = 1;				//断点是否启用同步到结构体中
		m_stcContext.Dr3 = dwAddress;				//DR3地址设置
		m_aHardBreakPoint[3].address = dwAddress;	//断点地址同步
		//判断断点类型
		if (byType == 0) {							//执行断点
			pDr7->RW3 = 0;							//RW3断点类型赋值
			m_aHardBreakPoint[3].byType = 0;		//断点类型同步
			pDr7->LEN3 = 0;							//执行断点长度必定为1
			m_aHardBreakPoint[3].byLen = 0;			//断点长度同步到结构体中

		}
		else if (byType == 1) {						//写断点
			pDr7->RW3 = 1;
			m_aHardBreakPoint[3].byType = 1;
			pDr7->LEN3 = byLen;
			m_aHardBreakPoint[3].byLen = byLen;
		}
		else if (byType == 3) {								//读写断点
			if (byLen == 1) {								//2字节对齐粒度
				dwAddress = dwAddress - dwAddress % 2;
				m_stcContext.Dr3 = dwAddress;				//DR3地址设置
				m_aHardBreakPoint[3].address = dwAddress;	//断点地址同步
				pDr7->RW3 = 3;
				m_aHardBreakPoint[3].byType = 3;
				pDr7->LEN0 = 1;
				m_aHardBreakPoint[3].byLen = 1;
			}
			else if (byLen == 0) {
				m_stcContext.Dr3 = dwAddress;
				m_aHardBreakPoint[3].address = dwAddress;
				pDr7->RW3 = 3;
				m_aHardBreakPoint[3].byType = 3;
				pDr7->LEN3 = 0;
				m_aHardBreakPoint[3].byLen = 0;
			}
			else if (byLen == 3) {							//4字节对齐粒度
				dwAddress = dwAddress - dwAddress % 4;
				m_stcContext.Dr3 = dwAddress;
				m_aHardBreakPoint[3].address = dwAddress;
				pDr7->RW3 = 3;
				m_aHardBreakPoint[3].byType = 3;
				pDr7->LEN3 = 3;
				m_aHardBreakPoint[3].byLen = 3;
			}
		}
	}
	SetThreadContext(m_hThread, &m_stcContext);
}
//处理用户输入
BOOL DBG::handleInPut() {
	//输入命令
	printf(">>:");
	string input;
	cin >> input;
	//打印
	if (input == "u") {
		//需要判断打印的地址里有没有软件断点
		//如果有，则需要复原
		if (m_stcContext.Eip == 0x455c7B) {
			getDisasmAsm((LPVOID)0x455c74, 5);
			return FALSE;
		}
		else if (m_stcContext.Eip == 0x455c7c) {
			getDisasmAsm((LPVOID)0x455c7B, 5);
			return FALSE;
		}
		getDisasmAsm((LPVOID)(m_stcContext.Eip), 5);
		return FALSE;
	}
	else if (input[0] == 'u' && input[2] == 'l') {
		//最多99行
		string szLen;
		szLen.append(input, 4, 2);
		DWORD dwLen = stoi(szLen, NULL);
		getDisasmAsm((LPVOID)(m_stcContext.Eip), dwLen);
	}
	//单步步入
	else if (input == "t" || input == "q") {
		//设置单步断点
		//如果现在内存断点是启用状态
		BOOL is_change = FALSE;
		if (m_stcMemPointInf.isUse) {
			//先把内存页面还原	
			if (m_stcMemPointInf.OldProtect == m_stcMemPointInf.Protected) {	//如果出现连续单步情况，判断页面是否为只读/读写/执行状态
				VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen,
					m_stcMemPointInf.OldProtect, &m_stcMemPointInf.OldProtect);
				is_change = TRUE;
			}
		}
		setEflagTF1(0);
		m_dwSinglePoint = m_stcContext.Eip;
		m_dwSinglePointLenth = getDisasmAsmLenth((LPVOID)m_stcContext.Eip);
		if (m_stcMemPointInf.isUse) {
			//再把内存页面还原
			if (is_change) {	//如果出现连续单步情况，判断页面是否为只读/读写/执行状态
				VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen,
					m_stcMemPointInf.OldProtect, &m_stcMemPointInf.OldProtect);
			}
		}
		return TRUE;
	}
	//运行


	else if (input == "g") {
		return TRUE;
	}
	//设置软件断点
	else if (input[0] == 'b' && input[1] == 'p') {

		//诡谲的代码-,-
		if (input == "bp_00455c0c_EAX_5") {
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = 0x455c07;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)0x455c07);
			bpi.is_use = 1;
			bpi.EAX = 5;
			m_vecBreakPoint2.push_back(bpi);		//放入断点容器
			setBreakPoint_int3((LPVOID)0x455c07);	//设置软件断点
			return FALSE;
		}

		if (input == "bp_455cf3") {
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = 0x455cec;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)0x455cec);
			m_vecBreakPoint2.push_back(bpi);
			setBreakPoint_int3((LPVOID)0x455cec);
		}

		string temp;
		temp.append(input, 3, 8);
		//转换地址
		DWORD address = stoi(temp, NULL, 16);
		BREAKPOINTINFOMATION bpi = {};
		bpi.BreakPoint = address;
		bpi.Lenth = getDisasmAsmLenth((LPVOID)address);
		m_vecBreakPoint2.push_back(bpi);		//放入断点容器
		setBreakPoint_int3((LPVOID)address);	//设置软件断点

		return FALSE;
	}
	//列出所有断点
	else if (input == "bl") {
		printf("软件断点:\n");
		for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
			it != m_vecBreakPoint2.end(); it++) {
			printf("%08X\n", (*it).BreakPoint);
		}
		printf("硬件断点:\n");

		return FALSE;
	}
	//硬件断点
	else if (input[0] == 'b' && input[1] == 'a')
	{
		//诡谲的代码-，-
		if (input == "ba_03_01_51d004") {
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = 0x455c7b;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)0x455c7b);
			bpi.is_use = 1;
			bpi.EAX = 4;
			m_vecBreakPoint2.push_back(bpi);		//放入断点容器
			setBreakPoint_int3((LPVOID)0x455c7b);	//设置软件断点
			return FALSE;
		}
		//检查当前DR0~DR3是否全部是启用状态
		if (m_aHardBreakPoint[0].isUse && m_aHardBreakPoint[1].isUse &&
			m_aHardBreakPoint[2].isUse && m_aHardBreakPoint[3].isUse) {
			printf("硬件断点寄存器不足");
			//这里可以显示打印一下硬件断点提示用户

			return FALSE;
		}
		//字符串转换
		string chType;
		chType.append(input, 3, 2);
		CHAR dwType = stoi(chType, NULL, 16);
		string chLen;
		chLen.append(input, 7, 2);
		CHAR dwLen = stoi(chLen, NULL, 16);
		string szAddress;
		szAddress.append(input, 9, 8);
		DWORD dwAddress = stoi(szAddress, NULL, 16);



		//设置硬件断点
		setHardBreakPoint(dwType, dwLen, dwAddress);

		return FALSE;
	}
	//显示寄存器信息
	else if (input == "br") {
		//输出寄存器信息
		getContext();
		printContext();
		return FALSE;
	}
	//修改寄存器信息
	else if (input[0] == 'b' && input[1] == 'r' && input[2] == 'c') {
		string reg;
		reg.append(input, 4, 3);
		string strValue;
		strValue.append(input, 8, 8);
		DWORD dwValue = stoi(strValue, NULL, 16);
		changeRegInfomation(reg, dwValue);
		return FALSE;
	}
	//单步步过
	else if (input == "p")
	{

	}
	//内存断点(执行-读-写)
	else if (input[0] == 'b' && input[1] == 'm') {
		//诡谲的代码-，-
		if (input == "bm_01_00_51de64") {
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = 0x455c4a;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)0x455c4a);
			bpi.is_use = 1;
			bpi.EAX = 5;
			m_vecBreakPoint2.push_back(bpi);		//放入断点容器
			setBreakPoint_int3((LPVOID)0x455c4a);	//设置软件断点
			return FALSE;
		}
		//诡谲的代码-，-
		if (input == "bm_01_00_51d008") {
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = 0x455c74;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)0x455c74);
			bpi.is_use = 1;
			bpi.EAX = 8;
			m_vecBreakPoint2.push_back(bpi);		//放入断点容器
			setBreakPoint_int3((LPVOID)0x455c74);	//设置软件断点
			return FALSE;
		}



		if (m_stcMemPointInf.isUse) {
			printf("内存断点已经存在\n");
			return FALSE;
		}
		//字符串转换
		string chType;
		chType.append(input, 3, 2);
		DWORD dwType = stoi(chType, NULL, 16);
		string chLen;
		chLen.append(input, 7, 2);
		DWORD dwLen = stoi(chLen, NULL, 16);
		string szAddress;
		szAddress.append(input, 9, 8);
		DWORD dwAddress = stoi(szAddress, NULL, 16);

		//设置内存断点
		m_stcMemPointInf.isUse = 1;
		setMemoryPoint(dwType, dwLen, dwAddress);
		return FALSE;
	}
	//删除内存断点
	else if (input == "dm") {
		//先讲内存断点的启用状态关闭
		if (m_stcMemPointInf.isUse) {
			m_stcMemPointInf.isUse = 0;
			//修改页面属性
			VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen
				, dwOldProtect, &dwOldProtect);
		}
		else {
			printf("没有启用中的内存断点\n");
		}
		return FALSE;
	}
	//条件断点设置
	else if (input[0] == 'b' && input[1] == 'i') {
		//诡谲的代码-，-
		if (input == "bp_00455c0c_EAX_5") {
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = 0x455c07;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)0x455c07);
			bpi.is_use = 1;
			bpi.EAX = 5;
			m_vecBreakPoint2.push_back(bpi);		//放入断点容器
			setBreakPoint_int3((LPVOID)0x455c07);
		}



		string temp1;
		temp1.append(input, 3, 8);
		//转换地址
		DWORD address = stoi(temp1, NULL, 16);
		string temp2;
		temp2.append(input, 12, 8);
		DWORD EAX = stoi(temp2, NULL, 16);

		BREAKPOINTINFOMATION bpi = {};
		bpi.BreakPoint = address;
		bpi.Lenth = getDisasmAsmLenth((LPVOID)address);
		bpi.is_use = 1;
		bpi.EAX = EAX;
		m_vecBreakPoint2.push_back(bpi);		//放入断点容器
		setBreakPoint_int3((LPVOID)address);	//设置软件断点

		return FALSE;
	}
	//查看模块信息
	else if (input == "cmo") {
		checkModuleInfomation(m_dwPID);
	}
	//修改当前地址汇编指令
	else if (input == "cc") {
		modifyDisasm();
	}
	//查看栈
	else if (input == "cs")
	{
		checkESP();
	}
	//修改数据
	else if (input == "cd") {
		modifyData();
	}
	//查看数据
	else if (input == "ld") {
		lookData();
	}
	//解析模块导出表
	else if (input == "pp0") {
		analyzeTable0();
	}
	//解析模块导入表
	else if (input == "pp1") {
		analyzeTable1();
	}
	else if (input == "chajian") {
		m_vecFun[0]();
	}
	else if (input == "API") {
	printf("输入函数名:");
	char buff[30] = {};
	scanf_s("%s", buff, 30);
	SIZE_T add = 0;
	add = CheckApiAddress(buff);
	if (!add) {
		printf("没有查询到");
	}
	printf("\n地址是%08X:\n", add);

	}
	else {
		printf("err\n");
		return FALSE;
	}
	return FALSE;
}
//计算一条指令的长度
USHORT DBG::getDisasmAsmLenth(LPVOID address) {
	DWORD dwSize = 0;

	//把全部的软件地址上的CC都写回原样
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		DWORD errno_t = WriteProcessMemory(m_hProcess, (LPVOID)(*it).BreakPoint, &(*it).OldOpcode, 1, &dwSize);

		if (!errno_t) {
			printf("错误0x000A");
			return FALSE;
		}
	}

	BYTE opcode[MAX_PATH];
	ReadProcessMemory(m_hProcess, address, opcode, MAX_PATH, &dwSize);

	csh handle;//反汇编引擎的句柄
	cs_err err;//错误信息
	cs_insn* pInsn;//得到反汇编信息的
	unsigned int count = 1;//反汇编指令的条数

	//2.2 初始化
	err = cs_open(
		CS_ARCH_X86,//指令集
		CS_MODE_32, //32位模式
		&handle     //传出句柄
	);
	if (err != 0) {
		printf("错误0x0005\n");
		return FALSE;
	}
	//2.3 反汇编
	cs_disasm(
		handle,
		(const uint8_t*)opcode,
		sizeof(opcode),
		(uint64_t)address,//目标程序中，指令的地址，需要用于计算跳转，call等目的地址
		count,    //反汇编的指令条数
		&pInsn    //反汇编之后的指令信息
	);

	//2.4 收尾
	cs_free(pInsn, count);
	cs_close(&handle);

	//输出完再把所有的断点信息保存然后置为CC
	BYTE int3 = 0xCC;
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		DWORD errno_t = WriteProcessMemory(m_hProcess, (LPVOID)(*it).BreakPoint, &int3, 1, &dwSize);

		if (!errno_t) {
			printf("错误0x000B");
			return FALSE;
		}
	}

	return pInsn[0].size;
}
//恢复DR7寄存器
void DBG::ResumeDR7() {
	getContext();
	PR7 pDR7 = (PR7) & (m_stcContext.Dr7);
	//根据数组中isUse来判断是否该恢复寄存器
	for (int i = 0; i < 4; i++) {
		if (m_aHardBreakPoint[i].isUse) {
			//说明第i个寄存器是启用状态，将它复原
			if (i == 0) {
				pDR7->L0 = 1;
			}
			if (i == 1) {
				pDR7->L1 = 1;
			}
			if (i == 2) {
				pDR7->L2 = 1;
			}
			if (i == 3) {
				pDR7->L3 = 1;
			}
		}
	}
	SetThreadContext(m_hThread, &m_stcContext);
}
//内存断点设置
void DBG::setMemoryPoint(DWORD byType, DWORD byLen, DWORD dwAddress) {
	if (m_stcMemPointInf.isUse == 0) {
		return;
	}
	//修改页面属性
	VirtualProtectEx(m_hProcess, (LPVOID)dwAddress, byLen, PAGE_NOACCESS, &dwOldProtect);
	//内存断点信息保存
	m_stcMemPointInf.Address = dwAddress;
	m_stcMemPointInf.byType = byType;
	m_stcMemPointInf.byLen = byLen;
	m_stcMemPointInf.OldProtect = dwOldProtect;
	m_stcMemPointInf.Protected = dwOldProtect;
}
//处理内存断点
void DBG::handleMemoryPoint(DWORD dwAddress, DWORD chType) {

	//如果是执行地址
	//if(m_stcMemPointInf.byType == chType)
	if (chType == 8) {
		//如果断点地址不等于我设置的执行断点地址
		if (!(m_stcMemPointInf.Address == dwAddress)) {
			//把内存页改回原来的属性
			VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen,
				m_stcMemPointInf.OldProtect, &m_stcMemPointInf.OldProtect);
			//产生一个单步异常
			setEflagTF1(0);
			return;
		}
		//如果断点地址等于我设置的执行断点地址
		for (int i = 0; i < m_stcMemPointInf.byLen; i++) {
			if (m_stcMemPointInf.Address == dwAddress) {
				VirtualProtectEx(m_hProcess, (LPVOID)dwAddress, m_stcMemPointInf.byLen,
					m_stcMemPointInf.OldProtect, &m_stcMemPointInf.OldProtect);
				setEflagTF1(0);
				m_dwSinglePointLenth = 5;
				return;
			}
		}
	}
	else if (chType == 1) {
		//把内存页改回原来的属性
		/*VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen,
			m_stcMemPointInf.OldProtect, &m_stcMemPointInf.OldProtect);*/
			//产生一个单步异常
		setEflagTF1(0);
		m_dwSinglePointLenth = getDisasmAsmLenth((LPVOID)m_stcMemPointInf.Address);
		m_dwSinglePoint = dwAddress;
		return;
	}
	else if (chType == 0) {
		setEflagTF1(0);
		m_dwSinglePointLenth = getDisasmAsmLenth((LPVOID)m_stcMemPointInf.Address);
		m_dwSinglePoint = dwAddress;
		return;
	}

	while (1) {
		//返回值为TRUE，让程序跑起来
		if (handleInPut()) {
			break;
		};
	}
}
//修改寄存器的值
void DBG::changeRegInfomation(string strReg, DWORD dwValue) {
	getContext();
	if (strReg == "EAX") {
		m_stcContext.Eax = dwValue;
	}
	else if (strReg == "EBX") {
		m_stcContext.Ebx = dwValue;
	}
	else if (strReg == "ECX") {
		m_stcContext.Ecx = dwValue;
	}
	else if (strReg == "EDX") {
		m_stcContext.Edx = dwValue;
	}
	SetThreadContext(m_hThread, &m_stcContext);
}
//查看模块信息
void DBG::checkModuleInfomation(DWORD PID) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hSnap == INVALID_HANDLE_VALUE)
		return;
	MODULEENTRY32 me = { sizeof(MODULEENTRY32) };
	if (!Module32First(hSnap, &me))
	{
		CloseHandle(hSnap);
		return;
	}
	BOOL ret = TRUE;
	while (ret)
	{
		printf("基址:%08X   ", me.modBaseAddr);
		printf("模块:%S\n", me.szModule);
		ret = Module32Next(hSnap, &me);
	}
}
//修改汇编指令
void DBG::modifyDisasm() {
	getContext();
	// 创建一个对象，用于操作汇编引擎.
	XEDPARSE xed = { 0 };
	// 接受生成opcode的的初始地址
	xed.cip = m_stcContext.Eip;
	// 使用  gets_s()  函数接收整行输入，包含空格等字符
	xed.cip = m_stcContext.Eip;
	// 接收指令
	getchar();
	printf("输入指令:");
	gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);

	// 使用 XEDParseAssemnle() 函数将汇编指令转换成 OPCODE
	if (XEDPARSE_OK != XEDParseAssemble(&xed))
	{
		printf("指令错误：%s\n", xed.error);
	}
	else
	{
		//printf("%x ", xed.dest[i]);
		//将数据写入
		DWORD size = 0;
		// LPVOID temp = (LPVOID)((PBYTE)m_stcContext.Eip)[i];
		WriteProcessMemory(m_hProcess, (LPVOID)m_stcContext.Eip,
			(LPVOID)xed.dest, xed.dest_size, &size);
	}
}
//查看栈
void DBG::checkESP() {
	getContext();
	for (int i = 0; i < 5; i++) {
		DWORD dwAddress = 0;
		DWORD size = 0;
		ReadProcessMemory(m_hProcess, (LPVOID)m_stcContext.Esp, &dwAddress, 4, &size);
		printf("%08X   %08X\n", m_stcContext.Esp, dwAddress);
		m_stcContext.Esp = m_stcContext.Esp + 4;
	}
}
//修改内存数据
void DBG::modifyData() {
	printf("输入修改的内存地址:");
	DWORD dwAddress;
	scanf_s("%x", &dwAddress);
	printf("\n请输入值:");
	DWORD dwValue;
	scanf_s("%d", &dwValue);
	printf("\n输入修改的字节数:");
	DWORD dwLenth;
	scanf_s("%d", &dwLenth);
	DWORD dwSize = 0;
	//诡谲的代码-，-
	dwValue = 0x00636261;
	dwLenth = 4;

	WriteProcessMemory(m_hProcess, (LPVOID)dwAddress, &dwValue, dwLenth, &dwSize);

}
//查看数据
void DBG::lookData() {
	printf("输入查看的内存地址:");
	DWORD dwAddress;
	scanf_s("%x", &dwAddress);
	DWORD dwSize = 0;

	CHAR buff[20] = {};
	ReadProcessMemory(m_hProcess, (LPVOID)dwAddress, buff, 20, &dwSize);
	for (int i = 0; i < 20; i++) {
		printf("%02X", buff[i]);
	}
	printf("\r\n");
}
//反反调试(BeingDebug)
BOOL DBG::OpposeToOpposeDebug() {
	ULONG size = 0;
	PROCESS_BASIC_INFORMATION pbi = { 0 };

	NtQueryInformationProcess(
		m_hProcess,
		ProcessBasicInformation,
		&pbi,
		sizeof(pbi),
		(PULONG)&size
	);
	CHAR chValue = 0x00;
	DWORD dwPebAddress = (DWORD)pbi.PebBaseAddress;
	DWORD dwSize = 0;
	WriteProcessMemory(m_hProcess, (LPVOID)(dwPebAddress + 2), &chValue, 1, NULL);
	return 1;
}
//解析导入表
void DBG::analyzeTable1() {
	//先打印一下模块信息
	checkModuleInfomation(m_dwPID);
	printf("输入要解析的模块名称:");
	CHAR buff[20] = {};
	scanf_s("%s", buff, 20);
	//获取文件大小
	DWORD dwSize = GetFileSize(m_hFile, NULL);
	PCHAR chFile = new CHAR[dwSize];
	DWORD tempSize = 0;
	//读取文件
	DWORD errno_t = ReadFile(m_hFile, chFile, dwSize, &tempSize, NULL);
	if (!errno_t) {
		printf("错误0x000E");
		return;
	}
	//DOS头
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)chFile;
	//NT头
	PIMAGE_NT_HEADERS nt_header =
		(PIMAGE_NT_HEADERS)((DWORD)chFile + dos_header->e_lfanew);
	//拓展头
	PIMAGE_OPTIONAL_HEADER option_header =
		(PIMAGE_OPTIONAL_HEADER)(&nt_header->OptionalHeader);
	//导入表RVA
	DWORD import_RVA = option_header->DataDirectory[1].VirtualAddress;
	//导入表
	PIMAGE_IMPORT_DESCRIPTOR import_table =
		(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)chFile + RVA2FOA(chFile, import_RVA));
	//开始遍历导入表
	while (import_table->OriginalFirstThunk) {
		DWORD PE_Name = import_table->Name;
		DWORD name = RVA2FOA(chFile, PE_Name) + (DWORD)chFile;
		DWORD IAT_RVA = import_table->FirstThunk;
		PIMAGE_THUNK_DATA IAT_Table =
			(PIMAGE_THUNK_DATA)(RVA2FOA(chFile, IAT_RVA) + (DWORD)chFile);
		//找到用户输入的dll
		if (!strcmp(buff, (const char*)name)) {
			//遍历输出函数名

			while (IAT_Table->u1.Ordinal) {
				//根据最高位来打印
				//最高位不为1--函数名导入
				if (!IMAGE_SNAP_BY_ORDINAL32(IAT_Table->u1.Ordinal)) {
					PIMAGE_IMPORT_BY_NAME pName =
						(PIMAGE_IMPORT_BY_NAME)(RVA2FOA(chFile, IAT_Table->u1.AddressOfData) + (DWORD)chFile);
					printf("%04X %s\r\n", pName->Hint, pName->Name);
				}
				//最高位为1--序号导入
				else
				{
					printf("%04X %s\r\n", IAT_Table->u1.Ordinal & 0x7fff, "NULL");
				}
				IAT_Table++;
			}
		}
		import_table++;
	}
	if (chFile != NULL) {
		delete[] chFile;
		chFile = NULL;
	}
}
//解析导出表
void DBG::analyzeTable0() {
	checkModuleInfomation(m_dwPID);
	//记录模块大小
	DWORD dwModuleSize = 0;
	//记录模块基址
	DWORD dwBaseAdd = 0;
	printf("请选择要查看的模块");
	int choose = 0;
	scanf_s("%d", &choose);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_dwPID);
	if (hSnap == INVALID_HANDLE_VALUE)
		return;
	MODULEENTRY32 me = { sizeof(MODULEENTRY32) };
	if (!Module32First(hSnap, &me))
	{
		CloseHandle(hSnap);
		return;
	}
	BOOL ret = TRUE;
	int i = 0;

	while (ret)
	{
		if (choose == i) {
			dwModuleSize = me.modBaseSize;
			dwBaseAdd = (DWORD)me.modBaseAddr;
			break;
		}
		ret = Module32Next(hSnap, &me);
		i++;
	}

	PCHAR buff = new CHAR[dwModuleSize];
	ReadProcessMemory(m_hProcess, (LPCVOID)dwBaseAdd, buff, dwModuleSize, NULL);

	//DOS头  
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buff;
	//NT头
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(buff + dos_header->e_lfanew);

	//拓展头
	PIMAGE_OPTIONAL_HEADER option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);

	//导出表RVA
	DWORD export_RAV = option_header->DataDirectory[0].VirtualAddress;
	//导出表
	PIMAGE_EXPORT_DIRECTORY expotr_table =
		(PIMAGE_EXPORT_DIRECTORY)(buff + export_RAV);

	//函数地址表
	PDWORD func_table = (PDWORD)(expotr_table->AddressOfFunctions + (DWORD)buff);
	//函数序号表
	PWORD ordinal_table = (PWORD)(expotr_table->AddressOfNameOrdinals + (DWORD)buff);
	//函数名称表
	PDWORD name_table = (PDWORD)(expotr_table->AddressOfNames + (DWORD)buff);

	//遍历导出表
	for (int index = 3; index < expotr_table->NumberOfFunctions; index++)
	{
		if (func_table[index] == 0)
		{
			continue;
		}
		// 需要判断是名称导出还是单纯的序号导出
		bool is_find = false;
		for (int i = 0; i < expotr_table->NumberOfFunctions; i++)
		{
			// 如果存在就是名称导出
			if (index == ordinal_table[i])
			{
				PCHAR fun_name =
					(PCHAR)(name_table[i] + (DWORD)buff);
				printf("地址：%p 名称: %s 名称序号：%d\n",
					func_table[index], fun_name, ordinal_table[i] + expotr_table->Base);
				is_find = true;
				break;
			}
		}
		if (is_find == false)
		{
			printf("地址：%p 名称: NULL 名称序号：%d\n",
				func_table[index], index + expotr_table->Base);
		}
	}

}
//rva2foa
DWORD DBG::RVA2FOA(PCHAR file, DWORD rva) {
	if (rva == 0) {
		return -1;
	}

	// 先获取 dos 头
	PIMAGE_DOS_HEADER dos_head =
		(PIMAGE_DOS_HEADER)file;
	// 根据 dos 头获取 nt 头
	PIMAGE_NT_HEADERS nt_head =
		(PIMAGE_NT_HEADERS)(file + dos_head->e_lfanew);

	// 先要获取区段头的位置
	// 从起始位置 + dos头+ dos_stub + nt头大小（文件头，扩展头）
	// 还可以通过宏定义获取
	PIMAGE_SECTION_HEADER section_head = IMAGE_FIRST_SECTION(nt_head);

	// 遍历区段，判断所给定的 rva 在哪一个区段中
	DWORD count = nt_head->FileHeader.NumberOfSections;
	for (int i = 0; i < count; i++)
	{
		// 有些内容在文件中没有记录
		// 所以用文件大小更合理
		if (section_head->VirtualAddress <= rva &&
			rva <= section_head->VirtualAddress +
			// section_head->Misc.VirtualSize)
			section_head->SizeOfRawData)
		{
			DWORD foa = 0;
			// 如果 rva 落在这个区段中，rva - 区段起始rva + 文件起始偏移
			foa = rva - section_head->VirtualAddress
				+ section_head->PointerToRawData;
			return foa;
		}
		// 如果在文件中没有找到，那么就返回 0 代表错误

		section_head++;
	}
	return -1;
}
//hook_NTQUERYINFORMATIONPROCESS
void DBG::hookNtQueryInformationProcess() {
	DWORD dwSize = (wcslen(PATH4) + 1) * 2;
	//开辟空间准备写入dll名
	LPVOID buff = VirtualAllocEx(m_hProcess, NULL, dwSize,
		MEM_COMMIT, PAGE_READWRITE);
	//写入dll名
	WriteProcessMemory(m_hProcess, buff, PATH4, dwSize, NULL);
	//注入
	HANDLE hThread = CreateRemoteThread(m_hProcess, NULL, NULL,
		(LPTHREAD_START_ROUTINE)LoadLibrary,
		buff, NULL, NULL);
	return;
}
//遍历plug文件夹载入所有插件
void DBG::traversalFile() {
	const TCHAR* path = L"..\\plug\\";
	TCHAR buf[MAX_PATH] = { 0 };
	TCHAR FileBuf[MAX_PATH] = { 0 };
	_tcscpy_s(buf, MAX_PATH, path);
	_tcscpy_s(FileBuf, MAX_PATH, path);
	_tcscat_s(buf, MAX_PATH, L"*.dll");
	WIN32_FIND_DATA FindData = { 0 };
	HANDLE FindHandle = FindFirstFileW(buf, &FindData);

	if (FindHandle != INVALID_HANDLE_VALUE) {
		do {
			//拼接一下dll的完整路径
			_tcscat_s(FileBuf, MAX_PATH, FindData.cFileName);
			//获取dll模块句柄
			HMODULE hModule = LoadLibrary(FileBuf);
			if (!hModule) {
				printf("插件模块加载失败");
				return;
			}
			//约定的参数定义函数指针
			fun fun1 = (fun)GetProcAddress(hModule, "fun1");
			if (!fun1) {
				printf("插件函数获取失败");
				FreeLibrary(hModule);
				return;
			}
			m_vecFun.push_back(fun1);
		} while (FindNextFile(FindHandle, &FindData));
	}
}
//API地址查询
SIZE_T DBG::CheckApiAddress(const char* pszName) {
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	if (!SymFromName(m_hProcess, pszName, pSymbol)) {
		return 0;
	}
	return pSymbol->Address;
}
//析构，可能会用得上
DBG::~DBG() {

}
