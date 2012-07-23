#include <windows.h>

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

unsigned offset(unsigned src, unsigned dest) {
        unsigned way;
        src += 5;
        way = dest - src;
        return way;
     }

void hookfunc(unsigned sourceFunc, unsigned new_address, unsigned instead_call, unsigned bts, DWORD process_id) {
     
      unsigned char byte;
      DWORD rw = 0;
      HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
      unsigned temp_address[10];
      temp_address[0] = sourceFunc;
      temp_address[1] = new_address;
      
      for(int i = 0; i < bts; i++)
      {
        ReadProcessMemory(hProc, (LPCVOID) sourceFunc, &byte, sizeof(byte), &rw);
        WriteProcessMemory(hProc, (LPVOID) new_address++, &byte, sizeof(byte), &rw);
        byte = 0x90;
        WriteProcessMemory(hProc, (LPVOID) sourceFunc++, &byte, sizeof(byte), &rw);
      }
    
      sourceFunc = temp_address[0]; 
      byte = 0xE9;                     

      WriteProcessMemory(hProc, (LPVOID) sourceFunc, &byte, sizeof(byte), &rw);
      temp_address[3] = offset(sourceFunc, instead_call);
      WriteProcessMemory(hProc, (LPVOID) ++sourceFunc, &temp_address[3], sizeof(temp_address[3]), &rw);
    
      byte = 0xE9;    
      new_address = temp_address[1];
      new_address += bts; 

      WriteProcessMemory(hProc, (LPVOID) new_address++, &byte, sizeof(byte), &rw);

      temp_address[4] = offset(temp_address[1] + bts, temp_address[0] + 5);

      WriteProcessMemory(hProc, (LPVOID) new_address, &temp_address[4], sizeof(temp_address[4]), &rw);
    
      CloseHandle(hProc);
     }
     
int WINAPI originalMoved(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
	__asm NOP;
    __asm NOP;                            
    __asm NOP;
    __asm NOP;                          
    __asm NOP;
    __asm NOP;                            
    __asm NOP;
    __asm NOP;
    __asm NOP;
    __asm NOP;                            
    __asm NOP;
    __asm NOP;
    __asm NOP;
    __asm NOP;                            
    __asm NOP;
    __asm NOP;
    __asm NOP;
    __asm NOP;                            
    __asm NOP;
    __asm NOP;
    __asm NOP;
    __asm NOP;                            
    __asm NOP;
    __asm NOP;
    __asm NOP;
    __asm NOP;
    __asm NOP;
    __asm NOP;
    __asm NOP;
    __asm NOP;
}

int WINAPI originalBypassed(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
      
      /* Your code here */
           
    return originalMoved(hWnd, lpText, lpCaption, uType);
     }
     
// 入口
extern "C" void __declspec(dllexport) DLLjump()
{
	// debug privilege
    seDebugPrivilege();
    
	// DLL
    HINSTANCE hDLL = LoadLibrary(L"user32.dll");
    
	// MessageBoxA的地址
	unsigned msgbox_addr = (unsigned) GetProcAddress(hDLL, "MessageBoxA");
    
	MEMORY_BASIC_INFORMATION mbi;
    DWORD dwOldProtect;
	//查询函数所在的内存页的信息
    VirtualQuery((void*) msgbox_addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	// 请求修改权限
    VirtualProtect((PDWORD) mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    
    hookfunc((unsigned) msgbox_addr, (unsigned) &originalMoved, (unsigned) &originalBypassed, 7, GetCurrentProcessId());
}

BOOL APIENTRY DllMain (HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
   return TRUE;
}
