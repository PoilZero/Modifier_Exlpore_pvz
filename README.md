# 修改器初探：pvz修改器

## 上下文

### 初学者必看

> 作者：PoilZero（日日生鸽）
>
> 博客：http://poilzero.sipc115.club
>
> 第一次尝试研究修改器，选择pvz一方面是因为着是我童年的回忆
>
> 另一方面，pvz没啥保护哈哈，比较适合入门
>
> 本部分实现了最基础修改器的功能，其他更多修改pvz的功能也都是基于此：
>
> * 动调定位
> * 汇编审计
> * 汇编patch（动调patch，编写脚本）
>
> 其他的游戏修改器，或多或少都必须包含这些步骤，当然还会有以下其他的知识点（本文不涉及）：
>
> * 脱壳
> * 反反调试，反混淆
> * 钩子
> * 更多注入方式
> * ...
>
> 总之道阻且长，本文用于记录和分享，废话这么多的原因是作者很菜，请勿介意

### 环境

> 使用：
>
> * 游戏程序请使用英文原版1.0:  http://jspvz.com/download.htm
> * 修改器程序
>
> 研究：
>
> * Cheat Engine
> * OD/x32dbg
> * C++ IDE
>
> 参考：
>
> * https://docs.microsoft.com/en-us/windows/win32/api/
> * Cheat Engine自带的教程

## 动态调试实现

### 修改卡片恢复时间

CE模糊搜索自增变量，最后归零找到某一卡片时间变量，然后通过CE的写入监控来找到哪行代码对他进行了修改得到

`VA：0048728C    8347 24 01      add dword ptr ds:[edi+0x24],0x1`

![image.png](http://poilzero.sipc115.club/usr/uploads/2021/08/3813004126.png)

使用OD attach找到逻辑，当`ds:[edi+0x24]<=ds:[edi+0x28]`时，继续循环，当反条件成立时，卡片恢复

因此，只要nop掉着个jle即可

```assembly
0048728C    8347 24 01      add dword ptr ds:[edi+0x24],0x1
00487290    8B47 24         mov eax,dword ptr ds:[edi+0x24]
00487293    3B47 28         cmp eax,dword ptr ds:[edi+0x28]
00487296    7E 14           jle short popcapga.004872AC
```

如下，此时取消断点，pvz卡片已经无恢复

```assembly
0048728C    8347 24 01      add dword ptr ds:[edi+0x24],0x1
00487290    8B47 24         mov eax,dword ptr ds:[edi+0x24]
00487293    3B47 28         cmp eax,dword ptr ds:[edi+0x28]
00487296    90              nop
00487297    90              nop
```

经过测试无aslr，该代码段的代码地址不会改变

### 修改阳光

同上可以查询得到

* 获得阳光：`00430A11 - 01 88 60550000  - add [eax+00005560],ecx`
* 消耗阳光：`0041BA76 - 89 B7 60550000  - mov [edi+00005560],esi`

![image.png](http://poilzero.sipc115.club/usr/uploads/2021/08/2695049977.png)

同上，修改种植不损耗阳光

```assembly
# 原始的
0041BA72 | 7F 0C                    | jg popcapgame1.41BA80                           |
0041BA74 | 2BF3                     | sub esi,ebx                                     |
0041BA76 | 89B7 60550000            | mov dword ptr ds:[edi+5560],esi                 | 种植损耗阳光
0041BA7C | B0 01                    | mov al,1                                        |
0041BA7E | 5E                       | pop esi                                         |
0041BA7F | C3                       | ret                                             |
# 修改为
0041BA72 | 7F 0C                    | jg popcapgame1.41BA80                           |
0041BA74 | 90                       | nop                                             | 修改
0041BA75 | 90                       | nop                                             | 修改
0041BA76 | 89B7 60550000            | mov dword ptr ds:[edi+5560],esi                 | 种植损耗阳光
0041BA7C | B0 01                    | mov al,1                                        |
0041BA7E | 5E                       | pop esi                                         |
0041BA7F | C3                       | ret                                             |
```

同上，捡起阳光获得无限阳光

```assembly
# 原始的
00430A0E | 8B46 04                  | mov eax,dword ptr ds:[esi+4]                    | esi+4:"8迥\x15"
00430A11 |                          | add dword ptr ds:[eax+5560],ecx                 | 增加阳光
00430A17 | 8B88 60550000            | mov ecx,dword ptr ds:[eax+5560]                 |
00430A1D | 81F9 06270000            | cmp ecx,2706                                    |
00430A23 | 7E 78                    | jle popcapgame1.430A9D                          |
00430A25 | C780 60550000 06270000   | mov dword ptr ds:[eax+5560],2706                |
00430A2F | EB 6C                    | jmp popcapgame1.430A9D                          |
# 修改为
00430A0E | 8B46 04                  | mov eax,dword ptr ds:[esi+4]                    | esi+4:"8迥\x15"
00430A11 | 01A0 60550000            | add dword ptr ds:[eax+5560],esp                 | 增加阳光 修改
00430A17 | 8B88 60550000            | mov ecx,dword ptr ds:[eax+5560]                 |
00430A1D | 81F9 06270000            | cmp ecx,2706                                    |
00430A23 | 7E 78                    | jle popcapgame1.430A9D                          |
00430A25 | C780 60550000 06270000   | mov dword ptr ds:[eax+5560],2706                |
00430A2F | EB 6C                    | jmp popcapgame1.430A9D                          |
```

## 编写脚本实现

### 技术总结

此处的进程表示游戏进程

* GetProcessPidByName：获得进程Pid
  * CreateToolhelp32Snapshot：创建内存快照（进程方式）
  * Process32First，Process32Next：枚举快照中的进程
* OpenProcess：获得进程句柄（注意句柄权限，否则后续操作失败）
* PatchGame：修改进程中的数据/代码
  * VirtualProtectEx：修改进程对应位置的操作权限（分页保护机制）
  * WriteProcessMemory：修改进程对应位置的数据/代码

### 代码

```c++
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
```

