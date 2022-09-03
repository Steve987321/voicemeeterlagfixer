#include <iostream>
#include <Windows.h>

#include <TlHelp32.h>
#include <comdef.h>
#include <unordered_map>

int PRINT_AND_EXITFAIL(const char* msg) { std::cout << msg << std::endl; system("pause"); return EXIT_FAILURE; }
extern BOOL GetPIDFromName(const char* pName, DWORD& pid);
extern BOOL SetPrivilege(HANDLE hToken, LPCWSTR lpszPrivilege, BOOL bEnablePrivilege); 
extern std::unordered_map<DWORD, const char*> umap;

int main()
{
    DWORD pid                   = {};
    DWORD old_Priority          = {};
    HANDLE hProc                = NULL;
    HANDLE hToken               = NULL;
    TOKEN_PRIVILEGES tp         = {};

    //user vars
    bool skipAffinity           = false;
    DWORD_PTR procAffinity      = 4;                /*processor core it gets changed to (4 = core 2)*/
    const char* processName     = "audiodg.exe";
  
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) { return PRINT_AND_EXITFAIL("Failed to open token handle"); }
    if (!SetPrivilege(hToken, L"SeDebugPrivilege", TRUE)) { return PRINT_AND_EXITFAIL("Failed to set privelege"); }

    GetPIDFromName(processName,pid);
    
    if (pid == NULL) { return EXIT_FAILURE; }
    std::cout << "PID: [" << pid << "]" << std::endl;

    hProc = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
    if (hProc == NULL) { return PRINT_AND_EXITFAIL("Failed to open handle to audiodg.exe"); }

    old_Priority = GetPriorityClass(hProc);

    if (old_Priority == NULL) { return PRINT_AND_EXITFAIL("Failed to get process priority"); }

    auto priorityInfo = umap.find(old_Priority);

    if (old_Priority == ABOVE_NORMAL_PRIORITY_CLASS)
    {
        std::cout << "priority is already set to [" << priorityInfo->second << ":" << priorityInfo->first << ']' << std::endl;

        if (!skipAffinity) goto SETAFFINITY;
        else return EXIT_SUCCESS;
    }

    std::cout << "changing [" << priorityInfo->second << ":" << priorityInfo->first << "] to [" << umap.find(ABOVE_NORMAL_PRIORITY_CLASS)->second << ']' << std::endl;

    //set priority to ABOVE_NORMAL_PRIORITY_CLASS
    SetPriorityClass(hProc, ABOVE_NORMAL_PRIORITY_CLASS);

    if (skipAffinity) return EXIT_SUCCESS;

SETAFFINITY:
    DWORD_PTR processAffinityMask;
    DWORD_PTR systemAffinityMask;

    if (!GetProcessAffinityMask(hProc, &processAffinityMask, &systemAffinityMask)) { std::cout << "failed to get process affinity\n"; system("pause");  return EXIT_FAILURE; }

    if (processAffinityMask == procAffinity) { std::cout << "Process Affinity is already set to [" << procAffinity << "]\n"; system("pause"); return EXIT_FAILURE; }

   std::cout << "changing process priority" << std::endl;

   if (!SetProcessAffinityMask(hProc, procAffinity)) {
       std::cout << "Failed to set Affinity to [" << procAffinity << ']' << std::endl; 
       std::cout << "error: " << GetLastError() << std::endl;
       system("pause");
       return EXIT_FAILURE; 
   }
   Sleep(1000);
   return EXIT_SUCCESS;
}

std::unordered_map<DWORD, const char*> umap =
{
    {0x00008000, "ABOVE_NORMAL_PRIORITY_CLASS"},
    {0x00004000, "BELOW_NORMAL_PRIORITY_CLASS"},
    {0x00000080, "HIGH_PRIORITY_CLASS"},
    {0x00000040, "IDLE_PRIORITY_CLASS"},
    {0x00000020, "NORMAL_PRIORITY_CLASS"},
    {0x00100000, "PROCESS_MODE_BACKGROUND_BEGIN"},
    {0x00200000, "PROCESS_MODE_BACKGROUND_END"},
    {0x00000100, "REALTIME_PRIORITY_CLASS"}
};

BOOL GetPIDFromName(const char* pName,DWORD& pid)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return FALSE;
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        return FALSE;
    }
    do
    {
        _bstr_t b(pe32.szExeFile);
        const char* c = b;

        if (std::strcmp(pName, c) == 0)
        {
            pid = pe32.th32ProcessID;
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return TRUE;
}

BOOL SetPrivilege(HANDLE hToken, LPCWSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege) tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}