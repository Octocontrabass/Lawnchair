/* This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * the COPYING file for more details. */

#include <windows.h>
#include <winuser.h>
#include <winbase.h>

#ifndef INJECT_LCID
#define INJECT_LCID 1041
#endif

#ifndef INJECT_CPID
#define INJECT_CPID 932
#endif

// typedefs for kernel32 function pointers
typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE,char*);
typedef HMODULE (WINAPI *GETMODULEHANDLE)(wchar_t*);
typedef BOOL (WINAPI *VIRTUALPROTECT)(LPVOID,SIZE_T,DWORD,PDWORD);

// structure of data given to injected function
typedef struct {
    GETMODULEHANDLE GetModuleHandleR;
    GETPROCADDRESS GetProcAddressR;
    wchar_t kernel32_name[sizeof(L"kernel32.dll")];
    wchar_t gdi32_name[sizeof(L"gdi32.dll")];
    char virtualprotect_name[sizeof("VirtualProtect")];
    char getthreadlocale_name[sizeof("GetThreadLocale")];
    char gdigetcodepage_name[sizeof("GdiGetCodePage")];
} InjectionData;

/* Injected code. Currently replaces:
 * kernel32.dll: GetThreadLocale
 * gdi32.dll: GdiGetCodePage */
static void WINAPI Code(InjectionData* data)
{
    HMODULE module;
    VIRTUALPROTECT VirtualProtectR;
    DWORD protection;
    char *function;
    
    module = data->GetModuleHandleR( data->kernel32_name );
    VirtualProtectR = data->GetProcAddressR( module, data->virtualprotect_name );
    
    /* GetThreadLocale:
     * mov eax, INJECT_LCID
     * retn */
    function = (char *)data->GetProcAddressR( module, data->getthreadlocale_name );
    VirtualProtectR( function, 6, PAGE_EXECUTE_READWRITE, &protection );
    function[0] = 0xB8;
    function[1] = INJECT_LCID       & 0xFF;
    function[2] = INJECT_LCID >>  8 & 0xFF;
    function[3] = INJECT_LCID >> 16 & 0xFF;
    function[4] = INJECT_LCID >> 24 & 0xFF;
    function[5] = 0xC3;
    VirtualProtectR( function, 6, protection, &protection );
    
    module = data->GetModuleHandleR( data->gdi32_name );
    if( module != NULL )
    {
        /* GdiGetCodePage:
         * mov eax, INJECT_CPID
         * retn 4 */
        function = (char *)data->GetProcAddressR( module, data->gdigetcodepage_name );
        VirtualProtectR( function, 8, PAGE_EXECUTE_READWRITE, &protection );
        function[0] = 0xB8;
        function[1] = INJECT_CPID       & 0xFF;
        function[2] = INJECT_CPID >>  8 & 0xFF;
        function[3] = INJECT_CPID >> 16 & 0xFF;
        function[4] = INJECT_CPID >> 24 & 0xFF;
        function[5] = 0xC2;
        function[6] = 0x04;
        function[7] = 0x00;
        VirtualProtectR( function, 8, protection, &protection );
    }
    return;
}

// hack to figure out the compiled size of Code()
static void AfterCode(void) {}

int WINAPI wWinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPWSTR lpCmdLine,int nShowCmd)
{
    int argc = 0;
    wchar_t** argv;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HMODULE kernel32;
    ptrdiff_t codesize;
    char *dataptr;
    char *codeptr;
    char *stubptr;
    CONTEXT ctx;
    InjectionData data;
    char stub[22];
    
    argv = CommandLineToArgvW(lpCmdLine,&argc);
    if(argc != 2)
    {
        MessageBoxW(NULL,
            L"Invalid command line.",
            L"Error",MB_OK|MB_ICONERROR);
        return 0;
    }
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
    if(!CreateProcessW(NULL,argv[1],NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi))
    {
        MessageBoxW(NULL,
            L"CreateProcess failed.",
            L"Error",MB_OK|MB_ICONERROR);
        return 0;
    }
    
    kernel32 = GetModuleHandleW( L"kernel32.dll" );
    data.GetProcAddressR = (GETPROCADDRESS)GetProcAddress( kernel32, "GetProcAddress" );
    data.GetModuleHandleR = (GETMODULEHANDLE)GetProcAddress( kernel32, "GetModuleHandleW" );
    CopyMemory(&data.kernel32_name, L"kernel32.dll", sizeof(L"kernel32.dll"));
    CopyMemory(&data.gdi32_name, L"gdi32.dll", sizeof(L"gdi32.dll"));
    CopyMemory(&data.virtualprotect_name, "VirtualProtect", sizeof("VirtualProtect"));
    CopyMemory(&data.getthreadlocale_name, "GetThreadLocale", sizeof("GetThreadLocale"));
    CopyMemory(&data.gdigetcodepage_name, "GdiGetCodePage", sizeof("GdiGetCodePage"));
    
    codesize = (char *)AfterCode - (char *)Code;
    dataptr = (char *)VirtualAllocEx( pi.hProcess, NULL,
            sizeof(InjectionData) + codesize + sizeof(stub),
            MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    codeptr = dataptr + sizeof(InjectionData);
    stubptr = codeptr + codesize;
    WriteProcessMemory( pi.hProcess, dataptr, &data, sizeof(InjectionData), NULL );
    WriteProcessMemory( pi.hProcess, codeptr, Code, codesize, NULL );
    
    ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext( pi.hThread, &ctx );
    
    /* push return_address
     * pushfd
     * pushad
     * push dataptr
     * mov eax, codeptr
     * call eax
     * popad
     * popfd
     * retn */
    stub[ 0] = 0x68;
    stub[ 1] =            ctx.Eip       & 0xFF;
    stub[ 2] =            ctx.Eip >>  8 & 0xFF;
    stub[ 3] =            ctx.Eip >> 16 & 0xFF;
    stub[ 4] =            ctx.Eip >> 24 & 0xFF;
    stub[ 5] = 0x9C;
    stub[ 6] = 0x60;
    stub[ 7] = 0x68;
    stub[ 8] = (uintptr_t)dataptr       & 0xFF;
    stub[ 9] = (uintptr_t)dataptr >>  8 & 0xFF;
    stub[10] = (uintptr_t)dataptr >> 16 & 0xFF;
    stub[11] = (uintptr_t)dataptr >> 24 & 0xFF;
    stub[12] = 0xB8;
    stub[13] = (uintptr_t)codeptr       & 0xFF;
    stub[14] = (uintptr_t)codeptr >>  8 & 0xFF;
    stub[15] = (uintptr_t)codeptr >> 16 & 0xFF;
    stub[16] = (uintptr_t)codeptr >> 24 & 0xFF;
    stub[17] = 0xFF;
    stub[18] = 0xD0;
    stub[19] = 0x61;
    stub[20] = 0x9D;
    stub[21] = 0xC3;
    
    WriteProcessMemory( pi.hProcess, stubptr, stub, sizeof(stub), NULL );
    
    ctx.ContextFlags = CONTEXT_CONTROL;
    ctx.Eip = (uintptr_t)stubptr;
    SetThreadContext( pi.hThread, &ctx );
    
    ResumeThread( pi.hThread );
    return 0;
}

// reduce size by avoiding the C runtime
int WINAPI WinMainCRTStartup(void)
{
    ExitProcess( wWinMain( GetModuleHandleW( NULL ), NULL, GetCommandLineW(), SW_SHOWDEFAULT ) );
}
