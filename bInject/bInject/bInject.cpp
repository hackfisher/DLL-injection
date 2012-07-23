// bInject.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


/*----------------------------------
Changelog

0.1
    initial release
    
(c) by www.brickster.net
----------------------------------*/

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <fstream>

#include "ASCII.h"

// 定义fLoadLibrary函数指针，根据字符串得到HINSTANCE
typedef HINSTANCE (__stdcall *fLoadLibrary)(char*);

// 根据DLL句柄和字符串得到进程的地址?
typedef LPVOID (__stdcall *fGetProcAddress)(HINSTANCE, char*);

// fDLLjump DLL入口，函数指针
typedef void (*fDLLjump)(void);

// 结构体，包括两个函数，以及Inject DLL的路径和入口名称
struct INJECT
{
      fLoadLibrary LoadLibrary;
      fGetProcAddress GetProcAddress;
      char DLLpath[256];
      char DLLjump[16];
};

// 输入注入DLL信息，路径和入口函数，注入代码, 似乎是在被注入的进程里面执行的？
DWORD WINAPI InjectedCode(LPVOID addr)
{
	HINSTANCE hDll;
	fDLLjump DLLjump;
	INJECT* is = (INJECT*) addr;       
	hDll = is->LoadLibrary(is->DLLpath);
	DLLjump = (fDLLjump) is->GetProcAddress(hDll, is->DLLjump);
	// 进入DLL 执行DLLjump
	DLLjump();
	return 0;
}

// 标志位，为何要这么做？
void InjectedEnd()
{
     /* This is to calculate the size of InjectedCode */
}

// 启用进程的Debug权限
void seDebugPrivilege()
{
	TOKEN_PRIVILEGES priv;
	HANDLE hThis, hToken;
	LUID luid;
	hThis = GetCurrentProcess();
	OpenProcessToken(hThis, TOKEN_ADJUST_PRIVILEGES, &hToken);
	LookupPrivilegeValue(0, L"seDebugPrivilege", &luid);
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, false, &priv, 0, 0, 0);
	CloseHandle(hToken);
	CloseHandle(hThis);
}

// 根据进程名查找相应的进程ID
DWORD lookupProgramID(const char process[]) {
      HANDLE hSnapshot;
      PROCESSENTRY32 ProcessEntry;
      ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
      hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   
      if (Process32First(hSnapshot, &ProcessEntry))
         do
         {
			DWORD dwNum = WideCharToMultiByte(CP_OEMCP,NULL,ProcessEntry.szExeFile,-1,NULL,0,NULL,FALSE);
			char *psText = new char[dwNum];
			if(!psText)
			{
				delete []psText;
			}
			
			WideCharToMultiByte (CP_OEMCP,NULL,ProcessEntry.szExeFile,-1,psText,dwNum,NULL,FALSE);
			printf("%s", psText);
          if (!strcmp(psText, process))
             {
              CloseHandle(hSnapshot);
              return ProcessEntry.th32ProcessID;
             }

		  delete []psText;
         } while(Process32Next(hSnapshot, &ProcessEntry));

      CloseHandle(hSnapshot);
      
      return 0;     
}

//
int main(int argc, char* argv[])
{
   HANDLE hProc;
   HINSTANCE hDll;
   LPVOID start, thread;
   DWORD codesize;
   INJECT is;
   
   // process name
   std::string pname;
   
   // print header
   ASCII::printBrickster();
   
   // enable debug privilege
   seDebugPrivilege();

   //MessageBox(NULL,L"MessageBoxText(内容)",L"Title(标题)",MB_OK);
   
   if (argc > 1) {
            pname = argv[1];
            
            hProc = OpenProcess(PROCESS_ALL_ACCESS, false, lookupProgramID(argv[1]));
   }
   else {
            std::cout << "\nPlease enter the name of the process (like program.exe): ";
            std::cin >> pname;

            hProc = OpenProcess(PROCESS_ALL_ACCESS, false, lookupProgramID(pname.c_str()));
   }
   
   if (hProc)
            std::cout << "\nProcess found and opened.";
   else {
            std::cout << "\nFailed opening process.\n";
            system("PAUSE");
            return 0;
   }

   if (argc > 2) 
            strcpy(is.DLLpath, argv[2]);
   else {
            std::string dll;
        
            std::cout << "\nPlease enter the path of the DLL: ";
            std::cin >> dll;
            
            strcpy(is.DLLpath, dll.c_str());
   }
   
   std::ifstream TestFile(is.DLLpath);
   
   if (TestFile)
            std::cout << "\nDLL file found.";
   else {
            std::cout << "\nDLL does not exist.\n";
            
            CloseHandle(hProc);
            
            system("PAUSE");
            return 0;
   }
   
   std::cout << "\nInjecting...";

   // 注入要用到的kernel32.dll中的两个函数
   hDll = LoadLibrary(L"kernel32.dll");
   is.LoadLibrary = (fLoadLibrary) GetProcAddress(hDll, "LoadLibraryA");
   is.GetProcAddress = (fGetProcAddress) GetProcAddress(hDll, "GetProcAddress");
   
   // 设置拷贝字符串
   strcpy(is.DLLjump, "DLLjump");
   
   // 被拷贝到被注入进程中的代码片段大小
   codesize = (DWORD) InjectedEnd - (DWORD) InjectedCode;
   
   // 在被注入进程中保留内存大小，包括INJECT结构体的大小，因为要用到
   start = VirtualAllocEx(hProc, 0, codesize + sizeof(INJECT), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
   // 被注入进程中线程开始的位置, InjectedCode()
   thread = (LPVOID) ((DWORD) start + sizeof(INJECT));
   

   //将代码拷贝到被注入进程中去，显示结构体，后是thread 代码
   /* Injecting the struct data first */
   WriteProcessMemory(hProc, start, (LPVOID) &is, sizeof(INJECT), NULL);

   /* Injecting the code */
   WriteProcessMemory(hProc, thread, (LPVOID) InjectedCode, codesize, NULL);

   std::cout << "\nCode has been injected.";
   
   std::cout << "\n\nProcess\n\t" << hProc << " (" << pname << ")\nSize of injected data\n\t" << sizeof(INJECT) << " bytes\nSize of injected code\n\t" << codesize << " bytes\nAt address\n\t" << start;
   
   std::cout << "\nDo you want to run the code now? (y/n) ";
   
   char a;
   
   std::cin >> a;
   
   switch (a) {
          case 'y':
               CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE) thread, start, 0, 0);
               std::cout << "\nThread started! Code is now up and running.\n";
               break;
          case 'n':
          default:
               std::cout << "\nTerminated.\n";
               break;
   }

   CloseHandle(hProc);
   
   system("PAUSE");
   
   return 0;
}



