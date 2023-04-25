#include"dbg1.0.h"


int main() {
	//setlocale(LC_ALL, "");
	DBG dbg;

	printf("1.打开进程  2.附加进程");
	DWORD choose = 0;
	scanf_s("%d", &choose);
	if (choose == 1) {
		printf("路径:");
		CHAR buff[MAX_PATH] = {0};
		scanf_s("%s", buff,MAX_PATH);
		WCHAR wbuff[MAX_PATH] = { 0 };
		MultiByteToWideChar(CP_ACP, NULL, buff, -1, wbuff, MAX_PATH);


		dbg.createOpen(wbuff);
	}
	else {
		printf("输入id");
		DWORD id = 0;
		scanf_s("%d", &id);
		dbg.addOpen(id);
	}
	

	dbg.debugEnentLoop();

	system("pause");
	return 0;
}