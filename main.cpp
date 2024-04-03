#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#define DLL_NAME "test.dll"

DWORD Process(char* ProcessName)
{
    HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32 ProcEntry;
    ProcEntry.dwSize = sizeof(ProcEntry);

    do
    {
        if (!strcmp(ProcEntry.szExeFile, ProcessName))
        {
            DWORD dwPID = ProcEntry.th32ProcessID;
            CloseHandle(hPID);
            return dwPID;
        }
    }
    while (Process32Next(hPID, &ProcEntry));
}

int main()
{
    DWORD dwProcess;
    char myDLL[MAX_PATH];

    GetFullPathName(DLL_NAME, MAX_PATH, myDLL, 0);

    dwProcess = Process("cs2.exe");
  
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcess);

    LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(myDLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(hProcess, allocatedMem, myDLL, sizeof(myDLL), NULL);
  
    CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, allocatedMem, 0, 0);
  
    CloseHandle(hProcess);
  
    MessageBox(NULL, "Injected successfully!", "Success", MB_OK);

    return 0;
}
