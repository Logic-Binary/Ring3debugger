#include"dbg1.0.h"


int main() {
	//setlocale(LC_ALL, "");
	DBG dbg;

	printf("1.�򿪽���  2.���ӽ���");
	DWORD choose = 0;
	scanf_s("%d", &choose);
	if (choose == 1) {
		printf("·��:");
		CHAR buff[MAX_PATH] = {0};
		scanf_s("%s", buff,MAX_PATH);
		WCHAR wbuff[MAX_PATH] = { 0 };
		MultiByteToWideChar(CP_ACP, NULL, buff, -1, wbuff, MAX_PATH);


		dbg.createOpen(wbuff);
	}
	else {
		printf("����id");
		DWORD id = 0;
		scanf_s("%d", &id);
		dbg.addOpen(id);
	}
	

	dbg.debugEnentLoop();

	system("pause");
	return 0;
}