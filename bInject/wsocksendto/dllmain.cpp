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
		// why need to add 5?
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
      
	  // 拷贝前7(bts)个byte到new_address
      for(int i = 0; i < bts; i++)
      {
        ReadProcessMemory(hProc, (LPCVOID) sourceFunc, &byte, sizeof(byte), &rw);
        WriteProcessMemory(hProc, (LPVOID) new_address++, &byte, sizeof(byte), &rw);
        byte = 0x90;
        WriteProcessMemory(hProc, (LPVOID) sourceFunc++, &byte, sizeof(byte), &rw);
      }
    
	  // reset
      sourceFunc = temp_address[0]; 
      // what does 0xE9 mean? asm JMP relative?
	  byte = 0xE9;                     

      WriteProcessMemory(hProc, (LPVOID) sourceFunc, &byte, sizeof(byte), &rw);
      
	  // copy and write offset, after 5 byte. jump to instead_call.
	  temp_address[3] = offset(sourceFunc, instead_call);
      WriteProcessMemory(hProc, (LPVOID) ++sourceFunc, &temp_address[3], sizeof(temp_address[3]), &rw);
    

	  // what does 0xE9 mean? asm jump?
      byte = 0xE9;    
      new_address = temp_address[1];

	  // after called code
      new_address += bts; 

	  // copy 0xE9
      WriteProcessMemory(hProc, (LPVOID) new_address++, &byte, sizeof(byte), &rw);

	  // the offset from current to origin, back to origin?
      temp_address[4] = offset(temp_address[1] + bts, temp_address[0] + 5);

      WriteProcessMemory(hProc, (LPVOID) new_address, &temp_address[4], sizeof(temp_address[4]), &rw);
    
	  // remember to close handle.
      CloseHandle(hProc);
     }
     
int originalMoved(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
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

int originalBypassed(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
    
       /* Your code here */
	 MessageBox(NULL,L"MessageBoxText(内容)",L"Title(标题)",MB_OK);
     return originalMoved(s, buf, len, flags, to, tolen);
     }
     
extern "C" void __declspec(dllexport) DLLjump()
{
    seDebugPrivilege();
    
    HINSTANCE hDLL = LoadLibrary(L"wsock32.dll");
    unsigned send_addr = (unsigned) GetProcAddress(hDLL, "sendto");
    MEMORY_BASIC_INFORMATION mbi;
    DWORD dwOldProtect;
    VirtualQuery((void*) send_addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    VirtualProtect((PDWORD) mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    
    hookfunc((unsigned) send_addr, (unsigned) &originalMoved, (unsigned) &originalBypassed, 5, GetCurrentProcessId());
}

BOOL APIENTRY DllMain (HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
   return TRUE;
}
