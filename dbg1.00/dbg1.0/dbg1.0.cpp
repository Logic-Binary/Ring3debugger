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
//�򿪵��Խ���(һ��)
BOOL DBG::createOpen(const TCHAR* pszFile) {
	if (pszFile == NULL) {
		printf("����0x0001\n");
		return false;
	}
	BOOL ret_value = FALSE;
	//����������
	STARTUPINFO stcStartupInfo = { sizeof(STARTUPINFO) };
	//������Ϣ
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
//���ӽ���
BOOL DBG::addOpen(DWORD dwPid) {
	DebugActiveProcess(dwPid);
	BOOL ret_value = FALSE;
	//����������
	STARTUPINFO stcStartupInfo = { sizeof(STARTUPINFO) };
	//������Ϣ
	PROCESS_INFORMATION stcProcInfo = { 0 };
	return ret_value;
}
//�ȴ������¼�(����)
void DBG::debugEnentLoop() {
	DWORD ret_value = 0;
	//������Ҫ�ж��²������쳣�ǵ����������Ļ��ǳ��������
	m_dwRetCode = DBG_CONTINUE;
	while (true) {
		//�ȴ������¼�
		//���յ������¼��ͻ᷵�أ����ҽ������¼���
		//��Ϣ��䵽�ṹ����
		ret_value = WaitForDebugEvent(&m_stcDeEvent, -1);
		if (ret_value == 0) {
			printf("����:0x0002\n");
			return;
		}
		//���ݵ����¼��ֱ���
		switch (m_stcDeEvent.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:			//�쳣�����¼�
			//�����쳣
			handleException(m_stcDeEvent.u.Exception);
			break;
		case CREATE_THREAD_DEBUG_EVENT:		//�����̵߳����¼�
			//printf("�̴߳���\n");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:	//�������̵����¼�
		{
			m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_stcDeEvent.dwProcessId);
			m_dwPID = m_stcDeEvent.dwProcessId;
			m_hFile = m_stcDeEvent.u.CreateProcessInfo.hFile;
			if (m_hProcess == NULL) {
				printf("����0x0004\n");
				return;
			}
			//��������
			OpposeToOpposeDebug();
			//dllע��
			hookNtQueryInformationProcess();
			//�������
			traversalFile();
			//���ų�ʼ��
			SymInitialize(m_hProcess, "S:\\�쳣�����\\dbg1.0д�ĺܳ�ª\\Debug\\", FALSE);
			//����ģ������ļ�
			TCHAR buff[MAX_PATH] = {};
			GetModuleFileName(NULL, buff, MAX_PATH);
			SymLoadModule64(m_hProcess, m_hFile, (PCSTR)buff, NULL,
				(DWORD64)0x00400000, 0);
			

			m_dwOEP = (DWORD)(m_stcDeEvent.u.CreateProcessInfo.lpStartAddress);
			printf("������ڵ�:%X\n", m_dwOEP);
			//��������ϵ�ṹ�����
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = m_dwOEP;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)m_dwOEP);
			m_vecBreakPoint2.push_back(bpi);
			setBreakPoint_int3((LPVOID)m_dwOEP);
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT:		//�˳��̵߳����¼�
			//printf("�߳��˳�\n");

			break;
		case EXIT_PROCESS_DEBUG_EVENT:		//�˳����̵����¼�
			//printf("�����˳�\n");

			if (m_hProcess != NULL) {
				CloseHandle(m_hProcess);
			}
			break;
		case LOAD_DLL_DEBUG_EVENT:			//load-dynamic-link-library (DLL) �����¼�
			break;
		case UNLOAD_DLL_DEBUG_EVENT:		//unload-DLL �����¼�
			break;
		case OUTPUT_DEBUG_STRING_EVENT:		//output-debugging-string �����¼�
			break;
		case RIP_EVENT:						//RIP �����¼�
			break;
		default:
			break;
		}
		//�ظ���ϵͳ
		//1.�Ҵ������� �����  --DBG_CONTINUE
		//2.�һ�û���� ���������Լ�ȥ����� --DBG_EXCEPTION_NOT_HANDLED
		ContinueDebugEvent(
			m_stcDeEvent.dwProcessId,
			m_stcDeEvent.dwThreadId,
			m_dwRetCode);
	}
	return;
}
//��ȡ�̻߳���
void DBG::getContext() {
	if (m_hThread != NULL) {
		CloseHandle(m_hThread);
	}

	m_stcContext.ContextFlags = CONTEXT_ALL;
	//ͨ��id��ȡ�߳̾��
	m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_stcDeEvent.dwThreadId);
	if (m_hThread == NULL) {
		printf("����0x0003\n");
		return;
	}
	GetThreadContext(m_hThread, &m_stcContext);
}
//��ӡ��ǰ��������
void DBG::printContext() {
	printf("EAX:%08X  EBX:%08X\nECX:%08X  EDX:%08X\n",
		m_stcContext.Eax,
		m_stcContext.Ebx,
		m_stcContext.Ecx,
		m_stcContext.Edx);
}
//��ӡ�������Ϣ
BOOL DBG::getDisasmAsm(LPVOID address, DWORD line) {

	DWORD dwSize = 0;
	//��ȫ���������ַ�ϵ�CC��д��ԭ��
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		DWORD errno_t = WriteProcessMemory(m_hProcess, (LPVOID)(*it).BreakPoint, &(*it).OldOpcode, 1, &dwSize);
		if (!errno_t) {
			printf("����0x000A");
			return FALSE;
		}
	}
	BYTE opcode[MAX_PATH];
	ReadProcessMemory(m_hProcess, address, opcode, MAX_PATH, &dwSize);
	csh handle;//���������ľ��
	cs_err err;//������Ϣ
	cs_insn* pInsn;//�õ��������Ϣ��
	unsigned int count = line;//�����ָ�������
	//2.2 ��ʼ��
	err = cs_open(
		CS_ARCH_X86,//ָ�
		CS_MODE_32, //32λģʽ
		&handle     //�������
	);
	if (err != 0) {
		printf("����0x0005\n");
		return FALSE;
	}
	//2.3 �����
	cs_disasm(
		handle,
		(const uint8_t*)opcode,
		sizeof(opcode),
		(uint64_t)address,//Ŀ������У�ָ��ĵ�ַ����Ҫ���ڼ�����ת��call��Ŀ�ĵ�ַ
		count,    //������ָ������
		&pInsn    //�����֮���ָ����Ϣ
	);
	for (size_t i = 0; i < count; i++)
	{
		printf("%llX |%s %s\n",
			pInsn[i].address,  //�ڴ��ַ
			pInsn[i].mnemonic, //ָ�������
			pInsn[i].op_str    //ָ�������
		);
	}
	//2.4 ��β
	cs_free(pInsn, count);
	cs_close(&handle);
	//������ٰ����еĶϵ���Ϣ����Ȼ����ΪCC
	BYTE int3 = 0xCC;
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		DWORD errno_t = WriteProcessMemory(m_hProcess, (LPVOID)(*it).BreakPoint, &int3, 1, &dwSize);
		if (!errno_t) {
			printf("����0x000B");
			return FALSE;
		}
	}
	return TRUE;
}
//int3����ϵ������
BOOL DBG::setBreakPoint_int3(LPVOID address) {
	DWORD dwSize = 0;
	DWORD errno_t = 0;
	BOOL is_find = FALSE;
	//���������ҵ���Ӧ�Ľṹ��ѵ�ַ��һ���ֽ�д��OldOpcode
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		if ((DWORD)address == (*it).BreakPoint) {
			errno_t = ReadProcessMemory(m_hProcess, address, &((*it).OldOpcode), 1, &dwSize);
			if (errno_t == 0) {
				printf("����0x0006");
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
		printf("����0x0007");
		return FALSE;
	}
	return true;
}
//�Ƴ�����ϵ�
BOOL DBG::removeBreakPoint_int3(LPVOID address) {
	DWORD dwSize = 0;
	DWORD errno_t = 0;
	BOOL is_find = FALSE;
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		if ((DWORD)address == (*it).BreakPoint) {
			errno_t = WriteProcessMemory(m_hProcess, address, &((*it).OldOpcode), 1, &dwSize);

			if (errno_t == 0) {
				printf("����0x0006");
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
//���õ���
//����Ϊ1��Ҫeip-1������Ϊ0����Ҫeip-1
BOOL DBG::setEflagTF1(DWORD exceptionType) {
	//��ȡ��ǰ�̻߳���
	DWORD errno_t = 0;
	getContext();
	if (exceptionType) {
		m_stcContext.Eip--;
	}
	m_pEflags = (PEFLAGS)&m_stcContext.EFlags;
	m_pEflags->TF = 1;
	errno_t = SetThreadContext(m_hThread, &m_stcContext);
	if (errno_t == 0) {
		printf("����0x0009");
		return FALSE;
	}
	return TRUE;
}
//���ϵ��Ƿ�������Ҫ�����
BOOL DBG::siftExpection(DWORD dwAddress, DWORD dwVritualAddress, DWORD dwType) {
	BOOL is_find = FALSE;

	//���Դ���
	//����Ƕ�ȡ�ϵ�
	//����쳣Ҳ�ǲ���Ҳ��д��
	if (m_stcMemPointInf.byType == dwType && m_stcMemPointInf.isUse) {
		//�����ʱ���Ե�ַ���������õĵ�ַ
		if (dwVritualAddress == m_stcMemPointInf.Address) {
			//��ҳ���ַ������д��ȥ
			VirtualProtectEx(
				m_hProcess,
				(LPVOID)m_stcMemPointInf.Address,
				m_stcMemPointInf.byLen,
				m_stcMemPointInf.OldProtect,
				&m_stcMemPointInf.OldProtect);
		}
		return TRUE;
	}

	//�����ϵ�
	if (m_dwSinglePoint + m_dwSinglePointLenth == dwAddress) {
		is_find = TRUE;
		if (m_stcMemPointInf.isUse) {
			//��ҳ���ַ������д��ȥ
			VirtualProtectEx(
				m_hProcess,
				(LPVOID)m_stcMemPointInf.Address,
				m_stcMemPointInf.byLen,
				m_stcMemPointInf.OldProtect,
				&m_stcMemPointInf.OldProtect);
		}
		return is_find;
	}
	//�ڴ�ϵ㲻Ϊ0
	if (dwVritualAddress != 0) {
		return TRUE;
	}
	//�����ʱ�ϵ�λ�õ����ڴ�ϵ�ĵ�ַ
	if ((dwAddress == m_stcMemPointInf.Address) && (m_stcMemPointInf.isUse)) {
		//��ҳ���ַ������д��ȥ
		VirtualProtectEx(
			m_hProcess,
			(LPVOID)m_stcMemPointInf.Address,
			m_stcMemPointInf.byLen,
			m_stcMemPointInf.OldProtect,
			&m_stcMemPointInf.OldProtect);
		return TRUE;
	}
	//����ϵ�
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		if ((*it).BreakPoint == dwAddress ||
			((*it).BreakPoint + (*it).Lenth == dwAddress)) {
			is_find = TRUE;
			return is_find;
		}
	}
	//Ӳ���ϵ�
	getContext();
	PR6 Pr6 = (PR6) & (m_stcContext.Dr6);
	//ֻҪ�����ĸ��Ĵ��������Ķϵ���
	if (Pr6->B0 || Pr6->B1 || Pr6->B2 || Pr6->B3) {
		is_find = TRUE;
		return is_find;
	}
	//���ܵĴ���-��-
	if (dwAddress == 0x455da0) {
		return TRUE;
	}


	return is_find;
}
//�����쳣(����)
BOOL DBG::handleException(EXCEPTION_DEBUG_INFO dbgInfo) {
	DWORD dwExceptionocde = dbgInfo.ExceptionRecord.ExceptionCode;
	DWORD address = (DWORD)(dbgInfo.ExceptionRecord.ExceptionAddress);
	BOOL is_find = FALSE;
	DWORD dwtemp = (DWORD)dbgInfo.ExceptionRecord.ExceptionInformation + 4;
	DWORD dwVritualAddress = *((PDWORD)dwtemp);
	//��������Լ�����Ҫ������쳣���Ź�ȥ
	is_find = siftExpection(address, dwVritualAddress, *(PDWORD)dbgInfo.ExceptionRecord.ExceptionInformation);
	if (!is_find) {
		//�ָ�һ��Ӳ���ϵ�ļĴ�������
		ResumeDR7();
		//����ڴ�ϵ�������״̬
		if (m_stcMemPointInf.isUse) {
			//���Ǹ���ַ��ҳ��ȫ������ΪPAGE_NOACCESS
			VirtualProtectEx(
				m_hProcess,
				(LPVOID)m_stcMemPointInf.Address,
				m_stcMemPointInf.byLen,
				m_stcMemPointInf.OldProtect,
				&m_stcMemPointInf.OldProtect);
		}
		return TRUE;
	}
	//�����쳣���ͣ��ֱ���
	switch (dwExceptionocde) {
		//int3
	case EXCEPTION_BREAKPOINT:
		handleInt3Point(address);
		break;
		//����
	case EXCEPTION_SINGLE_STEP:
		handleSingleStep(dwExceptionocde, address);
		break;
		//�ڴ�ϵ㴦��
	case EXCEPTION_ACCESS_VIOLATION:
		DWORD chType = *(PDWORD)dbgInfo.ExceptionRecord.ExceptionInformation;
		handleMemoryPoint(address, chType);
		break;
	}
	return TRUE;
}
//����int3�ϵ�
void DBG::handleInt3Point(DWORD address) {
	BOOL is_Find = FALSE;
	//�ж�һ���Ƿ����Լ���int3�ϵ�
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		if ((*it).BreakPoint == address) {
			is_Find = TRUE;
			break;
		}
	}
	//���ǵ����������Ķϵ㣬�Ź�ȥ
	if (!is_Find) {
		return;
	}
	//�ж��Ƿ���OEP�ϵ�
	if (address == m_dwOEP) {
		removeBreakPoint_int3((LPVOID)m_dwOEP);
		//printf("��ַ:%08X\n", address);
		//����������Ϣ(Ĭ��5��)
		getDisasmAsm((LPVOID)m_dwOEP, 5);
		//����Ĵ�����Ϣ
		getContext();
		printContext();
		//�������ϵ��Ƴ�
		m_pEflags = (PEFLAGS)&m_stcContext.EFlags;
		m_pEflags->TF = 0;
		SetThreadContext(m_hThread, &m_stcContext);
		//���ղ��ڷ��������ΪCC�ĵط��ָ�
		DWORD dwSize = 0;
		WriteProcessMemory(m_hProcess, (LPVOID)(m_vecBreakPoint2.begin()->BreakPoint),
			&(m_vecBreakPoint2.begin()->OldOpcode), 1, &dwSize);
		//��oep��Ϣ�ϵ�ɾ��
		m_vecBreakPoint2.erase(m_vecBreakPoint2.begin());
	}
	//����OEP�ϵ�
	else {
		//��ӡһ��
		//getDisasmAsm((LPVOID)address, 1);
		//��ָ��Ļ�ȥ�������õ����ϵ�
		removeBreakPoint_int3((LPVOID)address);
		//�����ַ������ϵ��ַ����������
		for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
			it != m_vecBreakPoint2.end(); it++) {
			if ((*it).BreakPoint == address) {
				return;
			}
		}
		//�����Ҳ�ǵ����ϵ�ĵ�ַ���ó���������
		if (address == m_dwSinglePoint) {
			return;
		}
	}
	while (1) {
		//����ֵΪTRUE���ó���������
		if (handleInPut()) {
			break;
		};
	}
}
//�������ϵ�
void DBG::handleSingleStep(DWORD dwexceptionocde, DWORD address) {
	getContext();//��ȡ�̻߳���
	BYTE int3 = 0xCC;
	DWORD dwSize = 0;
	//BOOL is_find = FALSE;			//�����ϵ��Ƿ�����
	//����������������ϵ㿪ͷд��cc
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		WriteProcessMemory(m_hProcess, (LPVOID)((*it).BreakPoint), &int3, 1, &dwSize);

		//���ܵĴ���-��-
		/*(*it).is_use = FALSE;
		if ((*it).BreakPoint == 0x455c4a ) {
			(*it).is_use = TRUE;
		}*/

		//��������ϵ��������Ҵ�ʱ�����쳣�ĵ�ַ���������ϵ��ַ
		if ((*it).is_use && (address == (*it).BreakPoint + (*it).Lenth)) {
			//������������� �ó������ִ��
			if ((m_stcContext.Eax != (*it).EAX)) {
				return;
			}
		}
	}
	//���ܵĴ���-,-
	if ((address == 0x455da0) && (m_stcContext.Eax != 5)) {
		return;
	}
	if ((address == 0x455c7b) && (m_stcContext.Eax != 8)) {
		return;
	}if ((address == 0x455c7c) && (m_stcContext.Eax != 4)) {
		return;
	}


	//getContext();					//��ȡ�̻߳���
	PR6 Pr6 = (PR6) & (m_stcContext.Dr6);
	//ֻҪ�����ĸ��Ĵ��������Ķϵ���
	if (Pr6->B0 || Pr6->B1 || Pr6->B2 || Pr6->B3)
	{
		//��ӡһ��,
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
		//��Dr7��L0 L1 L2 L3�ÿ� ��ָ��Ź�ȥ
		PR7 Pr7 = (PR7) & (m_stcContext.Dr7);
		Pr7->L0 = 0; Pr7->L1 = 0; Pr7->L2 = 0; Pr7->L3 = 0;
		SetThreadContext(m_hThread, &m_stcContext);
		//����һ�������ϵ�
		setEflagTF1(0);
	}

	//����ϵ�
	if (address == address + m_dwSinglePointLenth) {
		//�������ٴθ�Ϊ���ɶ��Ҷ�����
		VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen,
			m_stcMemPointInf.OldProtect, &m_stcMemPointInf.OldProtect);
	}


	//�û�����
	while (1) {
		//�������ֵΪture���ó���������
		if (handleInPut()) {
			break;
		};
	}
}
//����Ӳ���ϵ�
void DBG::setHardBreakPoint(BYTE byType, BYTE byLen, DWORD dwAddress) {
	//��ȡ�̻߳���
	getContext();
	PR7 pDr7 = (PR7)(&m_stcContext.Dr7);
	//�ж�һ��DR0~DR3�ĸ��ǿռĴ���
	if (!m_aHardBreakPoint[0].isUse) {				//DR0û�б�����
		pDr7->L0 = 1;								//DR0����
		m_aHardBreakPoint[0].isUse = 1;				//�ϵ��Ƿ�����ͬ�����ṹ����
		m_stcContext.Dr0 = dwAddress;				//DR0��ַ����
		m_aHardBreakPoint[0].address = dwAddress;	//�ϵ��ַͬ��
		//�ж϶ϵ�����
		if (byType == 0) {							//ִ�жϵ�
			pDr7->RW0 = 0;							//RW0�ϵ����͸�ֵ
			m_aHardBreakPoint[0].byType = 0;		//�ϵ�����ͬ��
			pDr7->LEN0 = 0;							//ִ�жϵ㳤�ȱض�Ϊ1
			m_aHardBreakPoint[0].byLen = 0;			//�ϵ㳤��ͬ�����ṹ����

		}
		else if (byType == 1) {						//д�ϵ�
			pDr7->RW0 = 1;
			m_aHardBreakPoint[0].byType = 1;
			pDr7->LEN0 = byLen;
			m_aHardBreakPoint[0].byLen = byLen;
		}
		else if (byType == 3) {								//��д�ϵ�
			if (byLen == 1) {								//2�ֽڶ�������
				dwAddress = dwAddress - dwAddress % 2;
				m_stcContext.Dr0 = dwAddress;				//DR0��ַ����
				m_aHardBreakPoint[0].address = dwAddress;	//�ϵ��ַͬ��
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
			else if (byLen == 3) {							//4�ֽڶ�������
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
	else if (!m_aHardBreakPoint[1].isUse) {			//DR1û�б�����
		pDr7->L1 = 1;								//DR1����
		m_aHardBreakPoint[1].isUse = 1;				//�ϵ��Ƿ�����ͬ�����ṹ����
		m_stcContext.Dr1 = dwAddress;				//DR1��ַ����
		m_aHardBreakPoint[1].address = dwAddress;	//�ϵ��ַͬ��
		//�ж϶ϵ�����
		if (byType == 0) {							//ִ�жϵ�
			pDr7->RW1 = 0;							//RW1�ϵ����͸�ֵ
			m_aHardBreakPoint[1].byType = 0;		//�ϵ�����ͬ��
			pDr7->LEN1 = 0;							//ִ�жϵ㳤�ȱض�Ϊ1
			m_aHardBreakPoint[1].byLen = 0;			//�ϵ㳤��ͬ�����ṹ����

		}
		else if (byType == 1) {						//д�ϵ�
			pDr7->RW1 = 1;
			m_aHardBreakPoint[1].byType = 1;
			pDr7->LEN1 = byLen;
			m_aHardBreakPoint[1].byLen = byLen;
		}
		else if (byType == 3) {								//��д�ϵ�
			if (byLen == 1) {								//2�ֽڶ�������
				dwAddress = dwAddress - dwAddress % 2;
				m_stcContext.Dr1 = dwAddress;				//DR1��ַ����
				m_aHardBreakPoint[1].address = dwAddress;	//�ϵ��ַͬ��
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
			else if (byLen == 3) {							//4�ֽڶ�������
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
	else if (!m_aHardBreakPoint[2].isUse) {	//DR2û�б�����
		pDr7->L2 = 1;								//DR2����
		m_aHardBreakPoint[2].isUse = 1;				//�ϵ��Ƿ�����ͬ�����ṹ����
		m_stcContext.Dr2 = dwAddress;				//DR2��ַ����
		m_aHardBreakPoint[2].address = dwAddress;	//�ϵ��ַͬ��
		//�ж϶ϵ�����
		if (byType == 0) {							//ִ�жϵ�
			pDr7->RW2 = 0;							//RW2�ϵ����͸�ֵ
			m_aHardBreakPoint[2].byType = 0;		//�ϵ�����ͬ��
			pDr7->LEN2 = 0;							//ִ�жϵ㳤�ȱض�Ϊ1
			m_aHardBreakPoint[2].byLen = 0;			//�ϵ㳤��ͬ�����ṹ����

		}
		else if (byType == 1) {						//д�ϵ�
			pDr7->RW2 = 1;
			m_aHardBreakPoint[2].byType = 1;
			pDr7->LEN2 = byLen;
			m_aHardBreakPoint[2].byLen = byLen;
		}
		else if (byType == 3) {								//��д�ϵ�
			if (byLen == 1) {								//2�ֽڶ�������
				dwAddress = dwAddress - dwAddress % 2;
				m_stcContext.Dr2 = dwAddress;				//DR2��ַ����
				m_aHardBreakPoint[2].address = dwAddress;	//�ϵ��ַͬ��
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
			else if (byLen == 3) {							//4�ֽڶ�������
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
	else if (!m_aHardBreakPoint[3].isUse) {			//DR3û�б�����
		pDr7->L3 = 1;								//DR3����
		m_aHardBreakPoint[3].isUse = 1;				//�ϵ��Ƿ�����ͬ�����ṹ����
		m_stcContext.Dr3 = dwAddress;				//DR3��ַ����
		m_aHardBreakPoint[3].address = dwAddress;	//�ϵ��ַͬ��
		//�ж϶ϵ�����
		if (byType == 0) {							//ִ�жϵ�
			pDr7->RW3 = 0;							//RW3�ϵ����͸�ֵ
			m_aHardBreakPoint[3].byType = 0;		//�ϵ�����ͬ��
			pDr7->LEN3 = 0;							//ִ�жϵ㳤�ȱض�Ϊ1
			m_aHardBreakPoint[3].byLen = 0;			//�ϵ㳤��ͬ�����ṹ����

		}
		else if (byType == 1) {						//д�ϵ�
			pDr7->RW3 = 1;
			m_aHardBreakPoint[3].byType = 1;
			pDr7->LEN3 = byLen;
			m_aHardBreakPoint[3].byLen = byLen;
		}
		else if (byType == 3) {								//��д�ϵ�
			if (byLen == 1) {								//2�ֽڶ�������
				dwAddress = dwAddress - dwAddress % 2;
				m_stcContext.Dr3 = dwAddress;				//DR3��ַ����
				m_aHardBreakPoint[3].address = dwAddress;	//�ϵ��ַͬ��
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
			else if (byLen == 3) {							//4�ֽڶ�������
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
//�����û�����
BOOL DBG::handleInPut() {
	//��������
	printf(">>:");
	string input;
	cin >> input;
	//��ӡ
	if (input == "u") {
		//��Ҫ�жϴ�ӡ�ĵ�ַ����û������ϵ�
		//����У�����Ҫ��ԭ
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
		//���99��
		string szLen;
		szLen.append(input, 4, 2);
		DWORD dwLen = stoi(szLen, NULL);
		getDisasmAsm((LPVOID)(m_stcContext.Eip), dwLen);
	}
	//��������
	else if (input == "t" || input == "q") {
		//���õ����ϵ�
		//��������ڴ�ϵ�������״̬
		BOOL is_change = FALSE;
		if (m_stcMemPointInf.isUse) {
			//�Ȱ��ڴ�ҳ�滹ԭ	
			if (m_stcMemPointInf.OldProtect == m_stcMemPointInf.Protected) {	//���������������������ж�ҳ���Ƿ�Ϊֻ��/��д/ִ��״̬
				VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen,
					m_stcMemPointInf.OldProtect, &m_stcMemPointInf.OldProtect);
				is_change = TRUE;
			}
		}
		setEflagTF1(0);
		m_dwSinglePoint = m_stcContext.Eip;
		m_dwSinglePointLenth = getDisasmAsmLenth((LPVOID)m_stcContext.Eip);
		if (m_stcMemPointInf.isUse) {
			//�ٰ��ڴ�ҳ�滹ԭ
			if (is_change) {	//���������������������ж�ҳ���Ƿ�Ϊֻ��/��д/ִ��״̬
				VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen,
					m_stcMemPointInf.OldProtect, &m_stcMemPointInf.OldProtect);
			}
		}
		return TRUE;
	}
	//����


	else if (input == "g") {
		return TRUE;
	}
	//��������ϵ�
	else if (input[0] == 'b' && input[1] == 'p') {

		//���ܵĴ���-,-
		if (input == "bp_00455c0c_EAX_5") {
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = 0x455c07;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)0x455c07);
			bpi.is_use = 1;
			bpi.EAX = 5;
			m_vecBreakPoint2.push_back(bpi);		//����ϵ�����
			setBreakPoint_int3((LPVOID)0x455c07);	//��������ϵ�
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
		//ת����ַ
		DWORD address = stoi(temp, NULL, 16);
		BREAKPOINTINFOMATION bpi = {};
		bpi.BreakPoint = address;
		bpi.Lenth = getDisasmAsmLenth((LPVOID)address);
		m_vecBreakPoint2.push_back(bpi);		//����ϵ�����
		setBreakPoint_int3((LPVOID)address);	//��������ϵ�

		return FALSE;
	}
	//�г����жϵ�
	else if (input == "bl") {
		printf("����ϵ�:\n");
		for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
			it != m_vecBreakPoint2.end(); it++) {
			printf("%08X\n", (*it).BreakPoint);
		}
		printf("Ӳ���ϵ�:\n");

		return FALSE;
	}
	//Ӳ���ϵ�
	else if (input[0] == 'b' && input[1] == 'a')
	{
		//���ܵĴ���-��-
		if (input == "ba_03_01_51d004") {
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = 0x455c7b;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)0x455c7b);
			bpi.is_use = 1;
			bpi.EAX = 4;
			m_vecBreakPoint2.push_back(bpi);		//����ϵ�����
			setBreakPoint_int3((LPVOID)0x455c7b);	//��������ϵ�
			return FALSE;
		}
		//��鵱ǰDR0~DR3�Ƿ�ȫ��������״̬
		if (m_aHardBreakPoint[0].isUse && m_aHardBreakPoint[1].isUse &&
			m_aHardBreakPoint[2].isUse && m_aHardBreakPoint[3].isUse) {
			printf("Ӳ���ϵ�Ĵ�������");
			//���������ʾ��ӡһ��Ӳ���ϵ���ʾ�û�

			return FALSE;
		}
		//�ַ���ת��
		string chType;
		chType.append(input, 3, 2);
		CHAR dwType = stoi(chType, NULL, 16);
		string chLen;
		chLen.append(input, 7, 2);
		CHAR dwLen = stoi(chLen, NULL, 16);
		string szAddress;
		szAddress.append(input, 9, 8);
		DWORD dwAddress = stoi(szAddress, NULL, 16);



		//����Ӳ���ϵ�
		setHardBreakPoint(dwType, dwLen, dwAddress);

		return FALSE;
	}
	//��ʾ�Ĵ�����Ϣ
	else if (input == "br") {
		//����Ĵ�����Ϣ
		getContext();
		printContext();
		return FALSE;
	}
	//�޸ļĴ�����Ϣ
	else if (input[0] == 'b' && input[1] == 'r' && input[2] == 'c') {
		string reg;
		reg.append(input, 4, 3);
		string strValue;
		strValue.append(input, 8, 8);
		DWORD dwValue = stoi(strValue, NULL, 16);
		changeRegInfomation(reg, dwValue);
		return FALSE;
	}
	//��������
	else if (input == "p")
	{

	}
	//�ڴ�ϵ�(ִ��-��-д)
	else if (input[0] == 'b' && input[1] == 'm') {
		//���ܵĴ���-��-
		if (input == "bm_01_00_51de64") {
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = 0x455c4a;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)0x455c4a);
			bpi.is_use = 1;
			bpi.EAX = 5;
			m_vecBreakPoint2.push_back(bpi);		//����ϵ�����
			setBreakPoint_int3((LPVOID)0x455c4a);	//��������ϵ�
			return FALSE;
		}
		//���ܵĴ���-��-
		if (input == "bm_01_00_51d008") {
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = 0x455c74;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)0x455c74);
			bpi.is_use = 1;
			bpi.EAX = 8;
			m_vecBreakPoint2.push_back(bpi);		//����ϵ�����
			setBreakPoint_int3((LPVOID)0x455c74);	//��������ϵ�
			return FALSE;
		}



		if (m_stcMemPointInf.isUse) {
			printf("�ڴ�ϵ��Ѿ�����\n");
			return FALSE;
		}
		//�ַ���ת��
		string chType;
		chType.append(input, 3, 2);
		DWORD dwType = stoi(chType, NULL, 16);
		string chLen;
		chLen.append(input, 7, 2);
		DWORD dwLen = stoi(chLen, NULL, 16);
		string szAddress;
		szAddress.append(input, 9, 8);
		DWORD dwAddress = stoi(szAddress, NULL, 16);

		//�����ڴ�ϵ�
		m_stcMemPointInf.isUse = 1;
		setMemoryPoint(dwType, dwLen, dwAddress);
		return FALSE;
	}
	//ɾ���ڴ�ϵ�
	else if (input == "dm") {
		//�Ƚ��ڴ�ϵ������״̬�ر�
		if (m_stcMemPointInf.isUse) {
			m_stcMemPointInf.isUse = 0;
			//�޸�ҳ������
			VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen
				, dwOldProtect, &dwOldProtect);
		}
		else {
			printf("û�������е��ڴ�ϵ�\n");
		}
		return FALSE;
	}
	//�����ϵ�����
	else if (input[0] == 'b' && input[1] == 'i') {
		//���ܵĴ���-��-
		if (input == "bp_00455c0c_EAX_5") {
			BREAKPOINTINFOMATION bpi = {};
			bpi.BreakPoint = 0x455c07;
			bpi.Lenth = getDisasmAsmLenth((LPVOID)0x455c07);
			bpi.is_use = 1;
			bpi.EAX = 5;
			m_vecBreakPoint2.push_back(bpi);		//����ϵ�����
			setBreakPoint_int3((LPVOID)0x455c07);
		}



		string temp1;
		temp1.append(input, 3, 8);
		//ת����ַ
		DWORD address = stoi(temp1, NULL, 16);
		string temp2;
		temp2.append(input, 12, 8);
		DWORD EAX = stoi(temp2, NULL, 16);

		BREAKPOINTINFOMATION bpi = {};
		bpi.BreakPoint = address;
		bpi.Lenth = getDisasmAsmLenth((LPVOID)address);
		bpi.is_use = 1;
		bpi.EAX = EAX;
		m_vecBreakPoint2.push_back(bpi);		//����ϵ�����
		setBreakPoint_int3((LPVOID)address);	//��������ϵ�

		return FALSE;
	}
	//�鿴ģ����Ϣ
	else if (input == "cmo") {
		checkModuleInfomation(m_dwPID);
	}
	//�޸ĵ�ǰ��ַ���ָ��
	else if (input == "cc") {
		modifyDisasm();
	}
	//�鿴ջ
	else if (input == "cs")
	{
		checkESP();
	}
	//�޸�����
	else if (input == "cd") {
		modifyData();
	}
	//�鿴����
	else if (input == "ld") {
		lookData();
	}
	//����ģ�鵼����
	else if (input == "pp0") {
		analyzeTable0();
	}
	//����ģ�鵼���
	else if (input == "pp1") {
		analyzeTable1();
	}
	else if (input == "chajian") {
		m_vecFun[0]();
	}
	else if (input == "API") {
	printf("���뺯����:");
	char buff[30] = {};
	scanf_s("%s", buff, 30);
	SIZE_T add = 0;
	add = CheckApiAddress(buff);
	if (!add) {
		printf("û�в�ѯ��");
	}
	printf("\n��ַ��%08X:\n", add);

	}
	else {
		printf("err\n");
		return FALSE;
	}
	return FALSE;
}
//����һ��ָ��ĳ���
USHORT DBG::getDisasmAsmLenth(LPVOID address) {
	DWORD dwSize = 0;

	//��ȫ���������ַ�ϵ�CC��д��ԭ��
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		DWORD errno_t = WriteProcessMemory(m_hProcess, (LPVOID)(*it).BreakPoint, &(*it).OldOpcode, 1, &dwSize);

		if (!errno_t) {
			printf("����0x000A");
			return FALSE;
		}
	}

	BYTE opcode[MAX_PATH];
	ReadProcessMemory(m_hProcess, address, opcode, MAX_PATH, &dwSize);

	csh handle;//���������ľ��
	cs_err err;//������Ϣ
	cs_insn* pInsn;//�õ��������Ϣ��
	unsigned int count = 1;//�����ָ�������

	//2.2 ��ʼ��
	err = cs_open(
		CS_ARCH_X86,//ָ�
		CS_MODE_32, //32λģʽ
		&handle     //�������
	);
	if (err != 0) {
		printf("����0x0005\n");
		return FALSE;
	}
	//2.3 �����
	cs_disasm(
		handle,
		(const uint8_t*)opcode,
		sizeof(opcode),
		(uint64_t)address,//Ŀ������У�ָ��ĵ�ַ����Ҫ���ڼ�����ת��call��Ŀ�ĵ�ַ
		count,    //������ָ������
		&pInsn    //�����֮���ָ����Ϣ
	);

	//2.4 ��β
	cs_free(pInsn, count);
	cs_close(&handle);

	//������ٰ����еĶϵ���Ϣ����Ȼ����ΪCC
	BYTE int3 = 0xCC;
	for (vector<BREAKPOINTINFOMATION>::iterator it = m_vecBreakPoint2.begin();
		it != m_vecBreakPoint2.end(); it++) {
		DWORD errno_t = WriteProcessMemory(m_hProcess, (LPVOID)(*it).BreakPoint, &int3, 1, &dwSize);

		if (!errno_t) {
			printf("����0x000B");
			return FALSE;
		}
	}

	return pInsn[0].size;
}
//�ָ�DR7�Ĵ���
void DBG::ResumeDR7() {
	getContext();
	PR7 pDR7 = (PR7) & (m_stcContext.Dr7);
	//����������isUse���ж��Ƿ�ûָ��Ĵ���
	for (int i = 0; i < 4; i++) {
		if (m_aHardBreakPoint[i].isUse) {
			//˵����i���Ĵ���������״̬��������ԭ
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
//�ڴ�ϵ�����
void DBG::setMemoryPoint(DWORD byType, DWORD byLen, DWORD dwAddress) {
	if (m_stcMemPointInf.isUse == 0) {
		return;
	}
	//�޸�ҳ������
	VirtualProtectEx(m_hProcess, (LPVOID)dwAddress, byLen, PAGE_NOACCESS, &dwOldProtect);
	//�ڴ�ϵ���Ϣ����
	m_stcMemPointInf.Address = dwAddress;
	m_stcMemPointInf.byType = byType;
	m_stcMemPointInf.byLen = byLen;
	m_stcMemPointInf.OldProtect = dwOldProtect;
	m_stcMemPointInf.Protected = dwOldProtect;
}
//�����ڴ�ϵ�
void DBG::handleMemoryPoint(DWORD dwAddress, DWORD chType) {

	//�����ִ�е�ַ
	//if(m_stcMemPointInf.byType == chType)
	if (chType == 8) {
		//����ϵ��ַ�����������õ�ִ�жϵ��ַ
		if (!(m_stcMemPointInf.Address == dwAddress)) {
			//���ڴ�ҳ�Ļ�ԭ��������
			VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen,
				m_stcMemPointInf.OldProtect, &m_stcMemPointInf.OldProtect);
			//����һ�������쳣
			setEflagTF1(0);
			return;
		}
		//����ϵ��ַ���������õ�ִ�жϵ��ַ
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
		//���ڴ�ҳ�Ļ�ԭ��������
		/*VirtualProtectEx(m_hProcess, (LPVOID)m_stcMemPointInf.Address, m_stcMemPointInf.byLen,
			m_stcMemPointInf.OldProtect, &m_stcMemPointInf.OldProtect);*/
			//����һ�������쳣
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
		//����ֵΪTRUE���ó���������
		if (handleInPut()) {
			break;
		};
	}
}
//�޸ļĴ�����ֵ
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
//�鿴ģ����Ϣ
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
		printf("��ַ:%08X   ", me.modBaseAddr);
		printf("ģ��:%S\n", me.szModule);
		ret = Module32Next(hSnap, &me);
	}
}
//�޸Ļ��ָ��
void DBG::modifyDisasm() {
	getContext();
	// ����һ���������ڲ����������.
	XEDPARSE xed = { 0 };
	// ��������opcode�ĵĳ�ʼ��ַ
	xed.cip = m_stcContext.Eip;
	// ʹ��  gets_s()  ���������������룬�����ո���ַ�
	xed.cip = m_stcContext.Eip;
	// ����ָ��
	getchar();
	printf("����ָ��:");
	gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);

	// ʹ�� XEDParseAssemnle() ���������ָ��ת���� OPCODE
	if (XEDPARSE_OK != XEDParseAssemble(&xed))
	{
		printf("ָ�����%s\n", xed.error);
	}
	else
	{
		//printf("%x ", xed.dest[i]);
		//������д��
		DWORD size = 0;
		// LPVOID temp = (LPVOID)((PBYTE)m_stcContext.Eip)[i];
		WriteProcessMemory(m_hProcess, (LPVOID)m_stcContext.Eip,
			(LPVOID)xed.dest, xed.dest_size, &size);
	}
}
//�鿴ջ
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
//�޸��ڴ�����
void DBG::modifyData() {
	printf("�����޸ĵ��ڴ��ַ:");
	DWORD dwAddress;
	scanf_s("%x", &dwAddress);
	printf("\n������ֵ:");
	DWORD dwValue;
	scanf_s("%d", &dwValue);
	printf("\n�����޸ĵ��ֽ���:");
	DWORD dwLenth;
	scanf_s("%d", &dwLenth);
	DWORD dwSize = 0;
	//���ܵĴ���-��-
	dwValue = 0x00636261;
	dwLenth = 4;

	WriteProcessMemory(m_hProcess, (LPVOID)dwAddress, &dwValue, dwLenth, &dwSize);

}
//�鿴����
void DBG::lookData() {
	printf("����鿴���ڴ��ַ:");
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
//��������(BeingDebug)
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
//���������
void DBG::analyzeTable1() {
	//�ȴ�ӡһ��ģ����Ϣ
	checkModuleInfomation(m_dwPID);
	printf("����Ҫ������ģ������:");
	CHAR buff[20] = {};
	scanf_s("%s", buff, 20);
	//��ȡ�ļ���С
	DWORD dwSize = GetFileSize(m_hFile, NULL);
	PCHAR chFile = new CHAR[dwSize];
	DWORD tempSize = 0;
	//��ȡ�ļ�
	DWORD errno_t = ReadFile(m_hFile, chFile, dwSize, &tempSize, NULL);
	if (!errno_t) {
		printf("����0x000E");
		return;
	}
	//DOSͷ
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)chFile;
	//NTͷ
	PIMAGE_NT_HEADERS nt_header =
		(PIMAGE_NT_HEADERS)((DWORD)chFile + dos_header->e_lfanew);
	//��չͷ
	PIMAGE_OPTIONAL_HEADER option_header =
		(PIMAGE_OPTIONAL_HEADER)(&nt_header->OptionalHeader);
	//�����RVA
	DWORD import_RVA = option_header->DataDirectory[1].VirtualAddress;
	//�����
	PIMAGE_IMPORT_DESCRIPTOR import_table =
		(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)chFile + RVA2FOA(chFile, import_RVA));
	//��ʼ���������
	while (import_table->OriginalFirstThunk) {
		DWORD PE_Name = import_table->Name;
		DWORD name = RVA2FOA(chFile, PE_Name) + (DWORD)chFile;
		DWORD IAT_RVA = import_table->FirstThunk;
		PIMAGE_THUNK_DATA IAT_Table =
			(PIMAGE_THUNK_DATA)(RVA2FOA(chFile, IAT_RVA) + (DWORD)chFile);
		//�ҵ��û������dll
		if (!strcmp(buff, (const char*)name)) {
			//�������������

			while (IAT_Table->u1.Ordinal) {
				//�������λ����ӡ
				//���λ��Ϊ1--����������
				if (!IMAGE_SNAP_BY_ORDINAL32(IAT_Table->u1.Ordinal)) {
					PIMAGE_IMPORT_BY_NAME pName =
						(PIMAGE_IMPORT_BY_NAME)(RVA2FOA(chFile, IAT_Table->u1.AddressOfData) + (DWORD)chFile);
					printf("%04X %s\r\n", pName->Hint, pName->Name);
				}
				//���λΪ1--��ŵ���
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
//����������
void DBG::analyzeTable0() {
	checkModuleInfomation(m_dwPID);
	//��¼ģ���С
	DWORD dwModuleSize = 0;
	//��¼ģ���ַ
	DWORD dwBaseAdd = 0;
	printf("��ѡ��Ҫ�鿴��ģ��");
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

	//DOSͷ  
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buff;
	//NTͷ
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(buff + dos_header->e_lfanew);

	//��չͷ
	PIMAGE_OPTIONAL_HEADER option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);

	//������RVA
	DWORD export_RAV = option_header->DataDirectory[0].VirtualAddress;
	//������
	PIMAGE_EXPORT_DIRECTORY expotr_table =
		(PIMAGE_EXPORT_DIRECTORY)(buff + export_RAV);

	//������ַ��
	PDWORD func_table = (PDWORD)(expotr_table->AddressOfFunctions + (DWORD)buff);
	//������ű�
	PWORD ordinal_table = (PWORD)(expotr_table->AddressOfNameOrdinals + (DWORD)buff);
	//�������Ʊ�
	PDWORD name_table = (PDWORD)(expotr_table->AddressOfNames + (DWORD)buff);

	//����������
	for (int index = 3; index < expotr_table->NumberOfFunctions; index++)
	{
		if (func_table[index] == 0)
		{
			continue;
		}
		// ��Ҫ�ж������Ƶ������ǵ�������ŵ���
		bool is_find = false;
		for (int i = 0; i < expotr_table->NumberOfFunctions; i++)
		{
			// ������ھ������Ƶ���
			if (index == ordinal_table[i])
			{
				PCHAR fun_name =
					(PCHAR)(name_table[i] + (DWORD)buff);
				printf("��ַ��%p ����: %s ������ţ�%d\n",
					func_table[index], fun_name, ordinal_table[i] + expotr_table->Base);
				is_find = true;
				break;
			}
		}
		if (is_find == false)
		{
			printf("��ַ��%p ����: NULL ������ţ�%d\n",
				func_table[index], index + expotr_table->Base);
		}
	}

}
//rva2foa
DWORD DBG::RVA2FOA(PCHAR file, DWORD rva) {
	if (rva == 0) {
		return -1;
	}

	// �Ȼ�ȡ dos ͷ
	PIMAGE_DOS_HEADER dos_head =
		(PIMAGE_DOS_HEADER)file;
	// ���� dos ͷ��ȡ nt ͷ
	PIMAGE_NT_HEADERS nt_head =
		(PIMAGE_NT_HEADERS)(file + dos_head->e_lfanew);

	// ��Ҫ��ȡ����ͷ��λ��
	// ����ʼλ�� + dosͷ+ dos_stub + ntͷ��С���ļ�ͷ����չͷ��
	// ������ͨ���궨���ȡ
	PIMAGE_SECTION_HEADER section_head = IMAGE_FIRST_SECTION(nt_head);

	// �������Σ��ж��������� rva ����һ��������
	DWORD count = nt_head->FileHeader.NumberOfSections;
	for (int i = 0; i < count; i++)
	{
		// ��Щ�������ļ���û�м�¼
		// �������ļ���С������
		if (section_head->VirtualAddress <= rva &&
			rva <= section_head->VirtualAddress +
			// section_head->Misc.VirtualSize)
			section_head->SizeOfRawData)
		{
			DWORD foa = 0;
			// ��� rva ������������У�rva - ������ʼrva + �ļ���ʼƫ��
			foa = rva - section_head->VirtualAddress
				+ section_head->PointerToRawData;
			return foa;
		}
		// ������ļ���û���ҵ�����ô�ͷ��� 0 �������

		section_head++;
	}
	return -1;
}
//hook_NTQUERYINFORMATIONPROCESS
void DBG::hookNtQueryInformationProcess() {
	DWORD dwSize = (wcslen(PATH4) + 1) * 2;
	//���ٿռ�׼��д��dll��
	LPVOID buff = VirtualAllocEx(m_hProcess, NULL, dwSize,
		MEM_COMMIT, PAGE_READWRITE);
	//д��dll��
	WriteProcessMemory(m_hProcess, buff, PATH4, dwSize, NULL);
	//ע��
	HANDLE hThread = CreateRemoteThread(m_hProcess, NULL, NULL,
		(LPTHREAD_START_ROUTINE)LoadLibrary,
		buff, NULL, NULL);
	return;
}
//����plug�ļ����������в��
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
			//ƴ��һ��dll������·��
			_tcscat_s(FileBuf, MAX_PATH, FindData.cFileName);
			//��ȡdllģ����
			HMODULE hModule = LoadLibrary(FileBuf);
			if (!hModule) {
				printf("���ģ�����ʧ��");
				return;
			}
			//Լ���Ĳ������庯��ָ��
			fun fun1 = (fun)GetProcAddress(hModule, "fun1");
			if (!fun1) {
				printf("���������ȡʧ��");
				FreeLibrary(hModule);
				return;
			}
			m_vecFun.push_back(fun1);
		} while (FindNextFile(FindHandle, &FindData));
	}
}
//API��ַ��ѯ
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
//���������ܻ��õ���
DBG::~DBG() {

}
