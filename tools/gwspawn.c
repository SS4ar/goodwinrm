#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <wbemidl.h>
#include <oleauto.h>

static int put_char(wchar_t *out, size_t cap, size_t *pos, wchar_t c) {
    if (*pos + 1 >= cap) return 1;
    out[(*pos)++] = c;
    return 0;
}

static int put_run(wchar_t *out, size_t cap, size_t *pos, wchar_t c, size_t n) {
    if (*pos + n >= cap) return 1;
    for (size_t k = 0; k < n; k++) out[(*pos)++] = c;
    return 0;
}

static int build_cmdline(wchar_t *out, size_t cap, int argc, wchar_t **argv, int start) {
    size_t pos = 0;
    out[0] = 0;
    for (int i = start; i < argc; i++) {
        wchar_t *arg = argv[i];
        size_t len = wcslen(arg);
        if (i > start && put_char(out, cap, &pos, L' ')) return 1;
        if (put_char(out, cap, &pos, L'"')) return 1;
        size_t backslashes = 0;
        for (size_t j = 0; j < len; j++) {
            wchar_t c = arg[j];
            if (c == L'\\') {
                backslashes++;
                continue;
            }
            if (c == L'"') {
                if (put_run(out, cap, &pos, L'\\', backslashes * 2 + 1)) return 1;
                if (put_char(out, cap, &pos, L'"')) return 1;
                backslashes = 0;
                continue;
            }
            if (backslashes && put_run(out, cap, &pos, L'\\', backslashes)) return 1;
            backslashes = 0;
            if (put_char(out, cap, &pos, c)) return 1;
        }
        if (put_run(out, cap, &pos, L'\\', backslashes * 2)) return 1;
        if (put_char(out, cap, &pos, L'"')) return 1;
    }
    out[pos] = 0;
    return 0;
}

static int do_probe(void) {
    BOOL injob = FALSE;
    IsProcessInJob(GetCurrentProcess(), NULL, &injob);
    JOBOBJECT_BASIC_LIMIT_INFORMATION info;
    ZeroMemory(&info, sizeof(info));
    DWORD ret = 0;
    BOOL ok = QueryInformationJobObject(NULL, JobObjectBasicLimitInformation, &info, sizeof(info), &ret);
    printf("inJob=%d queryOk=%d LimitFlags=0x%08lX\n", injob, ok, ok ? (unsigned long)info.LimitFlags : 0UL);
    printf("BREAKAWAY_OK=%d SILENT_BREAKAWAY_OK=%d KILL_ON_JOB_CLOSE=%d\n",
           ok && (info.LimitFlags & JOB_OBJECT_LIMIT_BREAKAWAY_OK) ? 1 : 0,
           ok && (info.LimitFlags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) ? 1 : 0,
           ok && (info.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) ? 1 : 0);
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    wchar_t cl[] = L"cmd.exe /c exit 0";
    BOOL cr = CreateProcessW(NULL, cl, NULL, NULL, FALSE,
                             CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi);
    printf("breakawayCreate ok=%d err=%lu\n", cr, cr ? 0UL : GetLastError());
    if (cr) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    return 0;
}

static int do_breakaway(int argc, wchar_t **argv, int start) {
    wchar_t cl[8192];
    if (build_cmdline(cl, sizeof(cl) / sizeof(wchar_t), argc, argv, start)) {
        printf("ERR 87\n");
        return 1;
    }
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    BOOL cr = CreateProcessW(NULL, cl, NULL, NULL, FALSE,
                             CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                             NULL, NULL, &si, &pi);
    DWORD err = cr ? 0 : GetLastError();
    if (!cr) {
        printf("ERR %lu\n", err);
        return 1;
    }
    printf("PID %lu\n", (unsigned long)pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

static int do_wmi(int argc, wchar_t **argv, int start) {
    wchar_t cl[8192];
    if (build_cmdline(cl, sizeof(cl) / sizeof(wchar_t), argc, argv, start)) {
        printf("ERR 87\n");
        return 1;
    }
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) { printf("ERR 0x%08lX\n", (unsigned long)hr); return 1; }
    IWbemLocator *loc = NULL;
    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void **)&loc);
    if (FAILED(hr)) { printf("ERR 0x%08lX\n", (unsigned long)hr); return 1; }
    IWbemServices *svc = NULL;
    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    hr = loc->lpVtbl->ConnectServer(loc, ns, NULL, NULL, 0, NULL, 0, 0, &svc);
    SysFreeString(ns);
    if (FAILED(hr)) { printf("ERR 0x%08lX\n", (unsigned long)hr); return 1; }
    CoSetProxyBlanket((IUnknown *)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    IWbemClassObject *cls = NULL;
    BSTR cn = SysAllocString(L"Win32_Process");
    hr = svc->lpVtbl->GetObject(svc, cn, 0, NULL, &cls, NULL);
    SysFreeString(cn);
    if (FAILED(hr)) { printf("ERR 0x%08lX\n", (unsigned long)hr); return 1; }
    IWbemClassObject *in = NULL;
    BSTR m = SysAllocString(L"Create");
    hr = cls->lpVtbl->GetMethod(cls, m, 0, &in, NULL);
    SysFreeString(m);
    if (FAILED(hr)) { printf("ERR 0x%08lX\n", (unsigned long)hr); return 1; }
    VARIANT v;
    VariantInit(&v);
    v.vt = VT_BSTR;
    v.bstrVal = SysAllocString(cl);
    BSTR pcl = SysAllocString(L"CommandLine");
    in->lpVtbl->Put(in, pcl, 0, &v, 0);
    SysFreeString(pcl);
    VariantClear(&v);
    IWbemClassObject *out = NULL;
    BSTR scls = SysAllocString(L"Win32_Process");
    BSTR sm = SysAllocString(L"Create");
    hr = svc->lpVtbl->ExecMethod(svc, scls, sm, 0, NULL, in, &out, NULL);
    SysFreeString(scls);
    SysFreeString(sm);
    if (FAILED(hr)) { printf("ERR 0x%08lX\n", (unsigned long)hr); return 1; }
    VARIANT pret;
    VariantInit(&pret);
    BSTR brv = SysAllocString(L"ReturnValue");
    out->lpVtbl->Get(out, brv, 0, &pret, NULL, NULL);
    SysFreeString(brv);
    long rv = 0;
    if (pret.vt == VT_I4) rv = pret.lVal;
    VariantClear(&pret);
    if (rv != 0) { printf("ERR %ld\n", rv); return 1; }
    VARIANT ppid;
    VariantInit(&ppid);
    BSTR bpid = SysAllocString(L"ProcessId");
    out->lpVtbl->Get(out, bpid, 0, &ppid, NULL, NULL);
    SysFreeString(bpid);
    long pid = (ppid.vt == VT_I4) ? ppid.lVal : -1;
    VariantClear(&ppid);
    printf("PID %ld\n", pid);
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) { printf("usage: gwspawn probe|breakaway|wmi ARGS...\n"); return 2; }
    if (!wcscmp(argv[1], L"probe")) return do_probe();
    if (!wcscmp(argv[1], L"breakaway")) return do_breakaway(argc, argv, 2);
    if (!wcscmp(argv[1], L"wmi")) return do_wmi(argc, argv, 2);
    printf("unknown mode\n");
    return 2;
}
