#include<stdio.h>
#include<stdlib.h>
#include<Windows.h>


extern "C" __declspec(dllexport) void fun();

void fun() {
	printf("123");
}

int a = 0;
int main() {

	WCHAR name[10] = {};
	scanf_s("%S", name,10);


	if (IsDebuggerPresent()) {
		printf("被调试");
	}
	else {
		printf("安全");
	}
	for (int i = 0; i < 10; i++) {
		a++;
		printf("%d",a);
	}

	printf("helloworld");

	system("pause");
	return 0;
}