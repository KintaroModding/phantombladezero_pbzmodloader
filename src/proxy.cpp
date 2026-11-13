#define PBZ_DLL
#include "core.hpp"
#include "mod-validation.hpp"
#include "proxy_config.hpp"
#include "embedded_script.hpp"
#include <atomic>
#include <mutex>

extern "C" void pbz_entry_gate();
extern "C" { void* pbz_original_entry=nullptr; }
static unsigned char entryBytes[14];
static HMODULE selfModule=nullptr;
static HANDLE logFile=INVALID_HANDLE_VALUE;
static INIT_ONCE versionOnce=INIT_ONCE_STATIC_INIT;
static HMODULE realVersion=nullptr;
static std::atomic<FARPROC> versionFunctions[proxyCount]{};
static fs::path modRoot;
static std::wstring slotSuffix;
static bool allowScriptPaks=true;
static std::atomic<bool> scriptDelivered{false};
static std::string deliveredScript;
static std::mutex mailLock;
static std::string mail;
static std::mutex changedLock;
static std::set<std::wstring> changedScripts;
using ValidateBytesFn = bool (*)(const GameString*,const GameBytes*);
using ValidateTextFn = bool (*)(const GameString*,const GameString*);
static std::array<ValidateBytesFn,4> originalValidationBytes{};
static ValidateTextFn originalValidationText=nullptr;
static void setMail(std::string message) { std::lock_guard<std::mutex> guard(mailLock); mail=std::move(message); }
static bool isSlot(const std::wstring& name) {
    auto lower=lowerSlashes(name);
    return lower.size()>slotSuffix.size() && lower.compare(lower.size()-slotSuffix.size(),slotSuffix.size(),slotSuffix)==0;
}
// The slot's first read starts the loader; each later read is the embedded manager asking for its mail.
static bool deliverSlot(const GameBytes* source) {
    if(!scriptDelivered.exchange(true)) {
        std::string script(embeddedScript,embeddedScriptSize);
        if(!replaceBytes(source,script)) {
            // The game's own start depends on this module, so it must still reach MainStart.
            log("MODs skipped: the embedded script does not fit this build's script slot; original game continues");
            script="require('puerts').__require('MainStart');";
            if(!replaceBytes(source,script)) return false;
        }
        deliveredScript=std::move(script);
        return true;
    }
    std::lock_guard<std::mutex> guard(mailLock);
    return replaceBytes(source,mail) || replaceBytes(source,mailError(0,"MOD list too long"));
}
static void noteChangedScript(const std::wstring& name) {
    std::lock_guard<std::mutex> guard(changedLock);
    if(changedScripts.insert(lowerSlashes(name)).second) log("changed game script allowed: "+utf8(name));
}
template<size_t Site>
static bool validateModBytes(const GameString* path,const GameBytes* source) noexcept {
    static_assert(Site<4);
    std::wstring name; const bool named=gameString(path,name);
    try { if(named && isSlot(name)) return deliverSlot(source); }
    catch(const std::exception& e) { log(std::string("script slot failed: ")+e.what()); }
    auto original=originalValidationBytes[Site];
    if(original && original(path,source)) return true;
    try {
        if(trustedModBytes(modRoot,path,source)) return true;
        if(named && allowScriptPaks && gameScriptPath(name)) { noteChangedScript(name); return true; }
    }
    catch(const std::exception& e) { log(std::string("MOD byte validation failed: ")+e.what()); }
    if(named) log("script bytes rejected: "+utf8(name));
    return false;
}
static bool validateModText(const GameString* path,const GameString* source) noexcept {
    if(originalValidationText && originalValidationText(path,source)) return true;
    std::wstring name; const bool named=gameString(path,name);
    try {
        if(named && isSlot(name) && sameScriptText((const unsigned char*)deliveredScript.data(),deliveredScript.size(),source)) return true;
        if(trustedModText(modRoot,path,source)) return true;
        if(named && allowScriptPaks && gameScriptPath(name)) { noteChangedScript(name); return true; }
    }
    catch(const std::exception& e) { log(std::string("MOD text validation failed: ")+e.what()); }
    if(named) log("script text rejected: "+utf8(name));
    return false;
}
static BOOL CALLBACK loadVersion(PINIT_ONCE,void*,void**) {
    wchar_t system[MAX_PATH+32]; UINT n=GetSystemDirectoryW(system,MAX_PATH);
    if(!n || n>=MAX_PATH) return FALSE;
    lstrcatW(system,PBZ_PROXY_DLL);
    realVersion=LoadLibraryExW(system,nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(!realVersion || realVersion==selfModule) return FALSE;
    return TRUE;
}
extern "C" FARPROC pbz_resolve_version(unsigned index) noexcept {
    const DWORD error=GetLastError();
    if(index>=proxyCount || !InitOnceExecuteOnce(&versionOnce,loadVersion,nullptr,nullptr)) {
        // A missing Windows API cannot be safely replaced with a fabricated return value.
        RaiseFailFastException(nullptr,nullptr,0);
        return nullptr;
    }
    auto function=versionFunctions[index].load(std::memory_order_relaxed);
    if(!function) {
        function=GetProcAddress(realVersion,versionNames[index]);
        // Optional exports vary across Windows versions. Resolve only the API used.
        if(!function) { RaiseFailFastException(nullptr,nullptr,0); return nullptr; }
        versionFunctions[index].store(function,std::memory_order_relaxed);
    }
    SetLastError(error); return function;
}
void log(const std::string& s) {
    if(logFile==INVALID_HANDLE_VALUE) return;
    // One file per game start: bounded, because the game's own warnings land here too.
    static std::atomic<unsigned long long> logged{0};
    constexpr unsigned long long logLimit=8*1024*1024;
    auto before=logged.fetch_add(s.size()+16);
    if(before>=logLimit) return;
    SYSTEMTIME t; GetLocalTime(&t); char time[40];
    snprintf(time,sizeof(time),"[%02u:%02u:%02u.%03u] ",t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
    std::string line=std::string(time)+s+"\r\n"; DWORD written;
    if(before+s.size()+16>=logLimit) line+="log limit reached; later lines are dropped\r\n";
    // FILE_APPEND_DATA and a single WriteFile per record allow the shutdown marker
    // to use this handle without a C++ lock or allocation in DllMain.
    WriteFile(logFile,line.data(),(DWORD)line.size(),&written,nullptr);
}
static DWORD WINAPI monitor(void* context) noexcept {
    U64 slab=(U64)context,next=0,starts=0;
    bool hotkeyRegistered=false,hotkeyWarning=false;
    constexpr int hotkeyId=0x5042;
    unsigned revision=1;
    try {
        for(;;) {
            drain(GetCurrentProcess(),slab,next);
            U64 current=0; read(GetCurrentProcess(),slab+4104,&current,8);
            if(current!=starts) { starts=current; log("main-start count="+std::to_string(starts)); }
            DWORD foregroundProcess=0;
            GetWindowThreadProcessId(GetForegroundWindow(),&foregroundProcess);
            bool focused=foregroundProcess==GetCurrentProcessId();
            if(focused && !hotkeyRegistered) {
                hotkeyRegistered=RegisterHotKey(nullptr,hotkeyId,MOD_ALT|MOD_NOREPEAT,VK_F5)!=0;
                if(!hotkeyRegistered && !hotkeyWarning) {
                    log("Alt+F5 registration failed; shortcut may be in use"); hotkeyWarning=true;
                }
            } else if(!focused && hotkeyRegistered) {
                UnregisterHotKey(nullptr,hotkeyId); hotkeyRegistered=false;
            }
            if(!focused) hotkeyWarning=false;
            MSG message{};
            bool requested=false;
            while(PeekMessageW(&message,nullptr,WM_HOTKEY,WM_HOTKEY,PM_REMOVE))
                if(message.wParam==hotkeyId && focused) requested=true;
            if(requested) {
                // Do not reserve another app's shortcut or queue repeated requests.
                UnregisterHotKey(nullptr,hotkeyId); hotkeyRegistered=false;
                try {
                    auto enabled=ini(modRoot/L"mods.ini",L"Loader",L"Enabled");
                    bool off=!enabled.empty() && number(enabled,1)==0;
                    setMail(mailMessage(revision,off?"{\"version\":1,\"root\":\""+jsonPath(modRoot)+"\",\"mods\":[]}":config(modRoot)));
                    log("hot reload published revision="+std::to_string(revision));
                }
                catch(const std::exception& e) {
                    log(std::string("hot reload preparation failed: ")+e.what());
                    setMail(mailError(revision,"Reload preparation failed; see loader.log"));
                }
                ++revision;
            }
            Sleep(50);
        }
    } catch(const std::exception& e) { log(std::string("ERROR monitor: ")+e.what()); }
    catch(...) { log("ERROR monitor: unknown exception"); }
    if(hotkeyRegistered) UnregisterHotKey(nullptr,hotkeyId);
    return 0;
}
extern "C" void pbz_initialize() noexcept {
    const DWORD savedError=GetLastError();
    // Restore the complete original entry before initialization. No instruction
    // relocation is necessary: the gate tail-jumps back to this exact address.
    DWORD old=0,unused=0;
    if(!VirtualProtect(pbz_original_entry,sizeof(entryBytes),PAGE_EXECUTE_READWRITE,&old)) {
        RaiseFailFastException(nullptr,nullptr,0); return;
    }
    std::memcpy(pbz_original_entry,entryBytes,sizeof(entryBytes));
    if(!VirtualProtect(pbz_original_entry,sizeof(entryBytes),old,&unused) ||
       !FlushInstructionCache(GetCurrentProcess(),pbz_original_entry,sizeof(entryBytes))) {
        RaiseFailFastException(nullptr,nullptr,0); return;
    }
    try {
        wchar_t exe[32768]; check(GetModuleFileNameW(nullptr,exe,32768)>0,"game path");
        const fs::path game=exe;
        const fs::path project=findProject(game);
        const fs::path root=project/L"PBZModLoader";
        fs::create_directories(root/L"mods");
        const auto logPath=root/L"loader.log";
        DeleteFileW(logPath.c_str());
        logFile=CreateFileW(logPath.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
        check(logFile!=INVALID_HANDLE_VALUE,"create DLL log");
        log("backend=dll; startup=exe-entry; debugger-api=none");
        log("entry-restored; pid="+std::to_string(GetCurrentProcessId()));
        HMODULE pinned=nullptr;
        check(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&pbz_initialize),&pinned),"pin proxy");
        check(InitOnceExecuteOnce(&versionOnce,loadVersion,nullptr,nullptr)!=FALSE,"load system proxy");
        wchar_t system[32768]; check(GetModuleFileNameW(realVersion,system,32768)>0,"system version path");
        log("proxy-system="+utf8(system));
        log("project="+utf8(project.wstring()));
        auto enabled=ini(root/L"mods.ini",L"Loader",L"Enabled");
        if(!enabled.empty() && number(enabled,1)==0) { log("MODs disabled by Loader.Enabled=0; original game continues"); SetLastError(savedError); return; }
        auto image=snapshotImage(GetCurrentProcess(),(U64)GetModuleHandleW(nullptr));
        const auto sites=resolveSites(image);
        { std::ostringstream message; message<<"signatures validated; call-rva=0x"<<std::hex<<sites.call<<" start-rva=0x"<<sites.start;
          for(auto rva:sites.loggers) message<<" logger-rva=0x"<<rva; log(message.str()); }
        // The embedded script reaches the game only through these validators.
        if(!sites.validateBytes) throw std::runtime_error("This build has no script validators to deliver the embedded script through");
        const auto startFile=project/START_FILE_PATH;
        std::wstring slot;
        if(usableStartFile(startFile,embeddedScriptSize)) slot=START_FILE_MODULE;
        else {
            std::error_code missing;
            if(fs::exists(startFile,missing)) log("start file too small or unreadable; a game script is the slot");
            slot=chooseScriptSlot(image).module;
        }
        slotSuffix=lowerSlashes(std::wstring(L"/content/javascript/")+slot+L".js");
        modRoot=fs::canonical(root);
        auto scriptPaks=ini(modRoot/L"mods.ini",L"Loader",L"AllowScriptPaks");
        allowScriptPaks=scriptPaks.empty() || number(scriptPaks,1)!=0;
        // A bad mods.ini must not stop the game: the manager reports it, and Alt+F5 can retry.
        try { setMail(mailMessage(0,config(modRoot))); }
        catch(const std::exception& e) { log(std::string("configuration failed: ")+e.what()); setMail(mailError(0,e.what())); }
        const auto base=(U64)GetModuleHandleW(nullptr);
        const auto validationCalls=captureValidationCalls(GetCurrentProcess(),base,image,sites);
        for(size_t i=0;i<originalValidationBytes.size();++i)
            originalValidationBytes[i]=reinterpret_cast<ValidateBytesFn>(validationCalls.targets[i]);
        originalValidationText=reinterpret_cast<ValidateTextFn>(validationCalls.targets[4]);
        const std::array<U64,5> validationHooks={{
            (U64)&validateModBytes<0>,(U64)&validateModBytes<1>,
            (U64)&validateModBytes<2>,(U64)&validateModBytes<3>,
            (U64)&validateModText
        }};
        auto installed=install(GetCurrentProcess(),base,image,sites,validationCalls,validationHooks,slot);
        log(std::string("script validation adapters installed; slot=")+utf8(slot)+"; embedded script bytes="+std::to_string(embeddedScriptSize)+
            "; changed game scripts="+(allowScriptPaks?"allowed":"not allowed"));
        log("native hooks installed; configuration published");
        HANDLE worker=CreateThread(nullptr,0,monitor,(void*)installed.slab,0,nullptr);
        if(worker) CloseHandle(worker); else log("ERROR monitor: CreateThread failed; MOD loading remains enabled");
    } catch(const std::exception& e) { log(std::string("MODs skipped: ")+e.what()+"; original game continues"); }
    catch(...) { log("MODs skipped: unknown initialization error; original game continues"); }
    SetLastError(savedError);
}

// Called with the Windows loader lock held. No file I/O, hash, STL allocation,
// LoadLibrary, thread creation/wait, configuration or PuerTS calls occur here.
__attribute__((noinline)) static void armEntry(HMODULE module) noexcept {
    // PROCESS_ATTACH is serialized. Keep long-path buffers out of thread stacks:
    // the game creates small-stack threads that also receive DLL notifications.
    static wchar_t exe[32768],dll[32768];
    DWORD a=GetModuleFileNameW(nullptr,exe,32768),b=GetModuleFileNameW(module,dll,32768);
    if(!a || a>=32768 || !b || b>=32768) return;
    wchar_t* exeName=wcsrchr(exe,L'\\'); wchar_t* dllName=wcsrchr(dll,L'\\');
    if(!exeName || !dllName) return;
    if(exeName-exe!=dllName-dll || _wcsnicmp(exe,dll,exeName-exe)) return;
    wchar_t guardName[80];
    swprintf(guardName,80,L"Local\\PBZModLoader-entry-%lu",GetCurrentProcessId());
    HANDLE guard=CreateMutexW(nullptr,FALSE,guardName);
    DWORD guardError=GetLastError();
    if(!guard) return;
    if(guardError==ERROR_ALREADY_EXISTS) { CloseHandle(guard); return; }
    // Keep the first handle until process exit; never wait under loader lock.
    // No platform path assumptions. Unsupported wrappers fail signature validation.
    auto base=(unsigned char*)GetModuleHandleW(nullptr);
    auto dos=(IMAGE_DOS_HEADER*)base;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE || dos->e_lfanew<=0 || dos->e_lfanew>0x100000) return;
    auto nt=(IMAGE_NT_HEADERS64*)(base+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC) return;
    DWORD rva=nt->OptionalHeader.AddressOfEntryPoint;
    if(!rva || rva>nt->OptionalHeader.SizeOfImage-sizeof(entryBytes)) return;
    void* entry=base+rva; DWORD old,unused;
    if(!VirtualProtect(entry,sizeof(entryBytes),PAGE_EXECUTE_READWRITE,&old)) return;
    std::memcpy(entryBytes,entry,sizeof(entryBytes)); pbz_original_entry=entry;
    unsigned char jump[14]={0xff,0x25,0,0,0,0}; auto gate=&pbz_entry_gate;
    std::memcpy(jump+6,&gate,8); std::memcpy(entry,jump,sizeof(jump));
    if(!FlushInstructionCache(GetCurrentProcess(),entry,sizeof(jump))) {
        std::memcpy(entry,entryBytes,sizeof(entryBytes)); pbz_original_entry=nullptr;
        FlushInstructionCache(GetCurrentProcess(),entry,sizeof(jump));
    }
    VirtualProtect(entry,sizeof(entryBytes),old,&unused);
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,void* reserved) {
    if(reason==DLL_PROCESS_ATTACH) {
        selfModule=module;
        // Only static imports are early enough to intercept the EXE entry point.
        // Accidentally installing multiple entries must not chain entry gates.
        if(reserved) armEntry(module);
    }
    else if(reason==DLL_PROCESS_DETACH && reserved && logFile!=INVALID_HANDLE_VALUE) {
        static const char marker[]="process-detach shutdown=true (not an exit-code assertion)\r\n";
        DWORD written; WriteFile(logFile,marker,sizeof(marker)-1,&written,nullptr);
        // No joins, loader calls or C++ stream destruction here. OS closes the handle.
    }
    return TRUE;
}
