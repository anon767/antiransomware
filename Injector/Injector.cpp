#include <windows.h>
#include <iostream>
#include <string>
#include <comdef.h>
#include <Wbemidl.h>
#include <fstream>
#include <sstream>

#include <thread> // For adding delay

#pragma comment(lib, "wbemuuid.lib")

#define WM_TRAYICON (WM_USER + 1)

// Global variables
NOTIFYICONDATA nid;
HINSTANCE hInst;
UINT hookedProcessCount = 0;

void UpdateTrayTooltip() {
    std::string tooltip = "Hooked Processes: " + std::to_string(hookedProcessCount);
#ifdef UNICODE
    std::wstring wtooltip = std::wstring(tooltip.begin(), tooltip.end());
    wcsncpy_s(nid.szTip, wtooltip.c_str(), _countof(nid.szTip));
#else
    strncpy_s(nid.szTip, tooltip.c_str(), _countof(nid.szTip));
#endif
    Shell_NotifyIcon(NIM_MODIFY, &nid);
}

void AddTrayIcon(HWND hwnd) {
    memset(&nid, 0, sizeof(nid));
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    UpdateTrayTooltip();
    Shell_NotifyIcon(NIM_ADD, &nid);
}

void RemoveTrayIcon() {
    Shell_NotifyIcon(NIM_DELETE, &nid);
}

void logToFile(const std::string& message) {
    wchar_t tempPath[MAX_PATH];
    DWORD result = GetEnvironmentVariableW(L"TEMP", tempPath, MAX_PATH);
    if (result > 0 && result < MAX_PATH) {
        std::wstringstream wss;
        wss << tempPath << L"\\injector_log.txt";
        std::wstring logFilePath = wss.str();

        // Convert std::wstring logFilePath to std::string
        std::string logFilePathStr(logFilePath.begin(), logFilePath.end());

        std::ofstream logFile(logFilePathStr, std::ios::app);
        if (logFile.is_open()) {
            logFile << message << std::endl;
            logFile.close();
        }
    }
}

bool InjectDLL(DWORD processID, const std::string& dllPath) {

    // Adding a small delay to avoid timing issues

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processID);
    if (!hProcess) {
        return false;
    }

    void* pRemoteMemory = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMemory) {
        logToFile("Failed to allocate memory in target process: " + std::to_string(GetLastError()));
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), dllPath.size() + 1, NULL)) {
        logToFile("Failed to write memory in target process: " + std::to_string(GetLastError()));
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("Kernel32.dll");
    if (!hKernel32) {
        logToFile("Failed to get handle to Kernel32.dll: " + std::to_string(GetLastError()));
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA) {
        logToFile("Failed to get address of LoadLibraryA: " + std::to_string(GetLastError()));
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteMemory, 0, NULL);
    if (!hRemoteThread) {
        logToFile("Failed to create remote thread: " + std::to_string(GetLastError()));
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);

    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);

    hookedProcessCount++;
    UpdateTrayTooltip();

    return true;
}

bool SetDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tokenPrivileges;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        logToFile("Failed to open process token: " + std::to_string(GetLastError()));
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPrivileges.Privileges[0].Luid)) {
        logToFile("Failed to look up privilege value: " + std::to_string(GetLastError()));
        CloseHandle(hToken);
        return false;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        logToFile("Failed to adjust token privileges: " + std::to_string(GetLastError()));
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        logToFile("The token does not have the specified privilege.");
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

class EventSink : public IWbemObjectSink {
    LONG m_lRef;
    bool bDone;
    std::string dllPath;

public:
    EventSink(const std::string& path) : m_lRef(0), bDone(false), dllPath(path) {}

    virtual ULONG STDMETHODCALLTYPE AddRef() {
        return InterlockedIncrement(&m_lRef);
    }

    virtual ULONG STDMETHODCALLTYPE Release() {
        LONG lRef = InterlockedDecrement(&m_lRef);
        if (lRef == 0)
            delete this;
        return lRef;
    }

    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppv = (IWbemObjectSink*)this;
            AddRef();
            return WBEM_S_NO_ERROR;
        }
        else {
            return E_NOINTERFACE;
        }
    }
    virtual HRESULT STDMETHODCALLTYPE Indicate(LONG lObjectCount, IWbemClassObject** apObjArray) {
        for (int i = 0; i < lObjectCount; i++) {
            VARIANT vtProp;
            HRESULT hr = apObjArray[i]->Get(_bstr_t(L"TargetInstance"), 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr)) {
                IUnknown* str = vtProp.punkVal;
                IWbemClassObject* pClassObj = NULL;
                str->QueryInterface(IID_IWbemClassObject, (void**)&pClassObj);

                VARIANT vtProcessID;
                hr = pClassObj->Get(L"ProcessId", 0, &vtProcessID, NULL, NULL);
                if (SUCCEEDED(hr)) {
                    DWORD processID = vtProcessID.uintVal;

                    // Inject the DLL into the new process
                    if (!InjectDLL(processID, dllPath)) {
                        std::cerr << "DLL injection failed for process ID: " << processID << std::endl;
                    }
                    VariantClear(&vtProcessID);
                }
                else {
                    logToFile("Failed to get ProcessId.");
                }

                pClassObj->Release();
                VariantClear(&vtProp);
            }
            else {
                logToFile("Failed to get TargetInstance.");
            }
        }
        return WBEM_S_NO_ERROR;
    }





    virtual HRESULT STDMETHODCALLTYPE SetStatus(
        LONG lFlags,
        HRESULT hResult,
        BSTR strParam,
        IWbemClassObject* pObjParam
    ) {
        return WBEM_S_NO_ERROR;
    }
};
void MonitorProcesses(const std::string& dllPath) {

    HRESULT hres;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IUnsecuredApartment* pUnsecApp = NULL;
    IUnknown* pStubUnk = NULL;
    IWbemObjectSink* pStubSink = NULL;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        logToFile("Failed to initialize COM library. Error code = 0x" + std::to_string(hres));
        return;
    }

    hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(hres)) {
        logToFile("Failed to initialize security. Error code = 0x" + std::to_string(hres));
        CoUninitialize();
        return;
    }

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&pLoc
    );

    if (FAILED(hres)) {
        logToFile("Failed to create IWbemLocator object. Error code = 0x" + std::to_string(hres));
        CoUninitialize();
        return;
    }

    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        logToFile("Could not connect. Error code = 0x" + std::to_string(hres));
        pLoc->Release();
        CoUninitialize();
        return;
    }

    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        logToFile("Could not set proxy blanket. Error code = 0x" + std::to_string(hres));
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    hres = CoCreateInstance(CLSID_UnsecuredApartment, NULL,
        CLSCTX_LOCAL_SERVER, IID_IUnsecuredApartment, (void**)&pUnsecApp);

    if (FAILED(hres)) {
        logToFile("Failed to create UnsecuredApartment. Error code = 0x" + std::to_string(hres));
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    EventSink* pSink = new EventSink(dllPath);
    pSink->AddRef();

    pUnsecApp->CreateObjectStub(pSink, &pStubUnk);
    pStubUnk->QueryInterface(IID_IWbemObjectSink, (void**)&pStubSink);

    hres = pSvc->ExecNotificationQueryAsync(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
        WBEM_FLAG_SEND_STATUS,
        NULL,
        pStubSink
    );

    if (FAILED(hres)) {
        logToFile("ExecNotificationQueryAsync failed. Error code = 0x" + std::to_string(hres));
        pSvc->Release();
        pLoc->Release();
        pStubSink->Release();
        pUnsecApp->Release();
        CoUninitialize();
        return;
    }




    pSvc->CancelAsyncCall(pStubSink);

    pSvc->Release();
    pLoc->Release();
    pStubSink->Release();
    pUnsecApp->Release();
    CoUninitialize();
}



LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_TRAYICON && lParam == WM_RBUTTONUP) {
        // Show a context menu when the tray icon is right-clicked
        POINT p;
        GetCursorPos(&p);
        HMENU hMenu = CreatePopupMenu();
        InsertMenu(hMenu, 0, MF_BYPOSITION | MF_STRING, 1, L"Exit");
        SetForegroundWindow(hwnd); // Required for the menu to appear in the foreground
        int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, p.x, p.y, 0, hwnd, NULL);
        if (cmd == 1) {
            PostQuitMessage(0);
        }
        DestroyMenu(hMenu);
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    hInst = hInstance;

    // Register the window class
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
#ifdef UNICODE
    wc.lpszClassName = L"TrayIconApp";
#else
    wc.lpszClassName = "TrayIconApp";
#endif
    RegisterClass(&wc);

    // Create a hidden window
#ifdef UNICODE
    HWND hwnd = CreateWindowEx(0, L"TrayIconApp", L"TrayIconApp", 0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
#else
    HWND hwnd = CreateWindowEx(0, "TrayIconApp", "TrayIconApp", 0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
#endif
    AddTrayIcon(hwnd);

    if (!SetDebugPrivilege()) {
        std::cerr << "Could not set privileges" << std::endl;
        logToFile("Could not set privileges");
        return 1;
    }

    std::string dllPath = "anticrypter.dll";

    logToFile("Starting MonitorProcesses thread...");
    std::thread monitorThread(MonitorProcesses, dllPath);
    if (monitorThread.joinable()) {
        logToFile("MonitorProcesses thread started successfully.");
    }
    else {
        logToFile("Failed to start MonitorProcesses thread.");
    }
    monitorThread.detach();

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    RemoveTrayIcon();
    return 0;
}
