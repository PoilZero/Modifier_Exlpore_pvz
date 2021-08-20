#include<windows.h>
#include<TlHelp32.h>
#include<stdio.h> 

DWORD dwPid;
HANDLE hTarget;

/*
	CreateToolhelp32Snapshot
	Process32First,Process32Next
	(OpenProcess)
*/
BOOL GetProcessPidByName(char *szProcessName, DWORD *dwPid){
	HANDLE l_hProcessSnapshot;
	l_hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 l_pe32;
	l_pe32.dwSize = sizeof(PROCESSENTRY32);
	if(l_hProcessSnapshot==INVALID_HANDLE_VALUE){
		return FALSE;
	}
	
	if(Process32First(l_hProcessSnapshot, &l_pe32)==0){
		return FALSE;
	}
	do{
		if(!strcmp(szProcessName, l_pe32.szExeFile)){
			*dwPid = l_pe32.th32ProcessID;
			break;
		}
//		printf("current read pn: %s | pid:%d\n", l_pe32.szExeFile, l_pe32.th32ProcessID);
	}while(Process32Next(l_hProcessSnapshot, &l_pe32));
	
	CloseHandle(l_hProcessSnapshot);
	return TRUE;
}

BOOL PatchGame(LPVOID lpAddr, BYTE* bBuff, DWORD dwSize){
	//LPVOID == void* 
	LPVOID lpBuff = (LPVOID)bBuff;
	DWORD dwOldProtect;
	VirtualProtectEx(hTarget, lpAddr, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	BOOL result  = WriteProcessMemory(
		hTarget
		, lpAddr, lpBuff 
		, dwSize, NULL
	);
	VirtualProtectEx(hTarget, lpAddr, dwSize, dwOldProtect, &dwOldProtect);
	
	if(result==0){
		printf("[-] 操作失败，错误代码：%d\n", GetLastError());
		return FALSE;
	}
	puts("[+] 操作成功，快去游戏里看看吧！");
	return TRUE;
}

void Menu(){
	puts("[+] 欢迎来到p0iL的pvz修改器0.0.1菜单");
	puts("- 显示菜单：0");
	puts("- 阳光修改：种植不损耗阳光：1");
	puts("- 阳光修改：捡起阳光超级加倍：2");
	puts("- 卡片修改：卡片瞬间恢复：3");
	puts("[+] 请输入对应数字回车执行对应操作");
}

int main(){
	if(GetProcessPidByName((char *)"popcapgame1.exe", &dwPid)==FALSE){
		puts("[-] can not found Pid");
		return 0;
	}
	
	hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if(hTarget==NULL){
		puts("[-] can not open this process"); 
		return 0;
	}
	
	Menu();
	while(TRUE){
		char readin;scanf("%c", &readin);
		switch(readin){
			case '0':
				Menu();
				break;
			case '1':{
				BYTE bBuff[] = {
					0x90, 0x90
				};
				PatchGame((LPVOID)0x0041BA74, bBuff, (DWORD)sizeof(bBuff));
				break;
			}
			case '2':{
				BYTE bBuff[] = {
					0x01, 0xA0, 0x60, 0x55, 0x00, 0x00
				};
				PatchGame((LPVOID)0x00430A11, bBuff, (DWORD)sizeof(bBuff));
				break;
			}
			case '3':{
				BYTE bBuff[] = {
					0x90, 0x90
				};
				PatchGame((LPVOID)0x00487296, bBuff, (DWORD)sizeof(bBuff));
				break;
			}
			default:
				puts("[-] 输入错误，可以输入0查看菜单"); 
				break;
		}
	}
 	return 0;
}
