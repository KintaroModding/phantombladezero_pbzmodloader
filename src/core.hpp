#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <array>
#include <set>
#include <map>
#include <regex>
#include <stdexcept>
#include <cstring>
#include <sstream>
#include <iomanip>
namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;
using U64 = unsigned long long;
constexpr size_t SLAB_SIZE=8192+256*2048;
#ifdef PBZ_DLL
void log(const std::string& s);
#else
std::ofstream output;
void log(const std::string& s) { std::cout<<s<<std::endl; if(output) { output<<s<<'\n'; output.flush(); } }
#endif
void check(bool ok,const char* op) { if(!ok) throw std::runtime_error(std::string(op)+" error="+std::to_string(GetLastError())); }
struct Handle {
    HANDLE h=nullptr;
    explicit Handle(HANDLE v=nullptr):h(v){}
    ~Handle(){if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h);}
    Handle(const Handle&)=delete;
    Handle& operator=(const Handle&)=delete;
};
std::string utf8(const std::wstring& s) {
    if(s.empty()) return {};
    int n=WideCharToMultiByte(CP_UTF8,0,s.data(),(int)s.size(),nullptr,0,nullptr,nullptr);
    std::string r(n,0); WideCharToMultiByte(CP_UTF8,0,s.data(),(int)s.size(),r.data(),n,nullptr,nullptr); return r;
}
std::string sha256(const fs::path& p) {
    BCRYPT_ALG_HANDLE a=nullptr; BCRYPT_HASH_HANDLE h=nullptr;
    if(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0) throw std::runtime_error("BCrypt provider");
    if(BCryptCreateHash(a,&h,nullptr,0,nullptr,0,0)<0) { BCryptCloseAlgorithmProvider(a,0); throw std::runtime_error("BCrypt hash"); }
    std::ifstream f(p,std::ios::binary); std::array<char,65536> b{}; unsigned char digest[32]; bool ok=bool(f);
    while(f) { f.read(b.data(),b.size()); if(BCryptHashData(h,(PUCHAR)b.data(),(ULONG)f.gcount(),0)<0) ok=false; }
    ok=ok && f.eof() && BCryptFinishHash(h,digest,32,0)>=0;
    BCryptDestroyHash(h); BCryptCloseAlgorithmProvider(a,0);
    if(!ok) throw std::runtime_error("Hash read failed");
    std::ostringstream s; for(auto v:digest) s<<std::hex<<std::setfill('0')<<std::setw(2)<<(int)v; return s.str();
}
std::wstring ini(const fs::path& p,const std::wstring& section,const wchar_t* key) {
    wchar_t buf[4096]; DWORD n=GetPrivateProfileStringW(section.c_str(),key,L"",buf,4096,p.c_str());
    if(n>=4095) throw std::runtime_error("Config value too long"); return std::wstring(buf,n);
}
int number(const std::wstring& s,int max) {
    if(s.empty() || s.find_first_not_of(L"0123456789")!=std::wstring::npos) throw std::runtime_error("Invalid numeric config");
    auto n=std::stoul(s); if(n>(unsigned)max) throw std::runtime_error("Config number out of range"); return (int)n;
}
std::string jsonPath(const fs::path& path) {
    auto text=utf8(path.generic_wstring());
    std::string result;
    for(char c:text) {
        if(c=='"' || c=='\\') result+='\\';
        if((unsigned char)c<32) throw std::runtime_error("Control character in path");
        result+=c;
    }
    return result;
}
// mods.ini is optional: without it, every discovered MOD loads. The result is JSON.
std::string config(const fs::path& root) {
    fs::path p=root/L"mods.ini";
    if(fs::is_regular_file(p) && ini(p,L"Loader",L"Version")!=L"1") throw std::runtime_error("Unsupported config version");
    auto countValue=ini(p,L"Loader",L"Count");
    int count=countValue.empty()?0:number(countValue,128); std::set<std::string> ids;
    struct Mod { std::string id,entry; bool enabled; };
    std::vector<Mod> mods;
    std::string result="{\"version\":1,\"root\":\""+jsonPath(fs::absolute(root))+"\",\"mods\":[";
    for(int i=0;i<count;++i) {
        auto section=L"Mod."+std::to_wstring(i);
        auto id=utf8(ini(p,section,L"Id")), entry=utf8(ini(p,section,L"Entry"));
        auto enabled=number(ini(p,section,L"Enabled"),1);
        if(!std::regex_match(id,std::regex("[A-Za-z0-9_-]+")) || !ids.insert(id).second ||
           !std::regex_match(entry,std::regex("mods/([A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\\.(js|ts)"))) throw std::runtime_error("Invalid or duplicate MOD: "+id);
        auto overrideValue=ini(p,L"Mods",fs::u8path(id).wstring().c_str());
        if(!overrideValue.empty()) enabled=number(overrideValue,1);
        mods.push_back({id,entry,enabled!=0});
    }
    // Only immediate child directories with main.ts/main.js are MODs; other files
    // are dependencies. Sort by ID so filesystem enumeration cannot reorder MODs.
    std::map<std::string,std::string> discovered;
    if(fs::is_directory(root/L"mods")) for(const auto& item:fs::directory_iterator(root/L"mods")) {
        auto id=utf8(item.path().filename().wstring());
        if(!item.is_directory() || !std::regex_match(id,std::regex("[A-Za-z0-9_-]+")) ||
           (!fs::is_regular_file(item.path()/L"main.js") && !fs::is_regular_file(item.path()/L"main.ts"))) continue;
        // JavaScript wins: a TypeScript source next to it is the author's, not for the player.
        auto entry="mods/"+id+(fs::is_regular_file(item.path()/L"main.js")?"/main.js":"/main.ts");
        bool configured=false;
        for(const auto& mod:mods) if(_stricmp(mod.id.c_str(),id.c_str())==0 ||
            _stricmp(fs::u8path(mod.entry).replace_extension().string().c_str(),fs::u8path(entry).replace_extension().string().c_str())==0) { configured=true; break; }
        if(!configured) discovered.emplace(id,entry);
    }
    for(const auto& [id,entry]:discovered) {
        auto enabled=ini(p,L"Mods",fs::u8path(id).wstring().c_str());
        mods.push_back({id,entry,enabled.empty() || number(enabled,1)!=0});
    }
    if(mods.size()>128) throw std::runtime_error("Too many MODs (maximum 128)");
    for(size_t i=0;i<mods.size();++i) {
        const auto& mod=mods[i];
        const auto& id=mod.id; auto entry=mod.entry; bool enabled=mod.enabled;
        if(enabled) {
            auto file=fs::weakly_canonical(root/fs::u8path(entry));
            auto relative=file.lexically_relative(fs::canonical(root/L"mods"));
            if(relative.empty() || *relative.begin()==L".." || !fs::is_regular_file(file)) throw std::runtime_error("Missing or escaped entry: "+entry);
        }
        // The player package holds no compiler. Say why such a MOD does not run.
        bool typescriptOnly=fs::u8path(entry).extension()==L".ts";
        if(typescriptOnly) {
            if(enabled) log("MOD "+id+" skipped: TypeScript source without main.js; its author must ship compiled JavaScript");
            enabled=false;
            entry=entry.substr(0,entry.size()-3)+".js";
        }
        if(i) result+=",";
        result+="{\"id\":\""+id+"\",\"enabled\":"+(enabled?"true":"false")+",\"entry\":\""+entry+"\"";
        if(typescriptOnly) result+=",\"note\":\"TypeScript source without main.js\"";
        result+="}";
    }
    return result+"]}";
}
// What the embedded manager reads from the DLL: the current MOD list or the reason there is none.
std::string mailMessage(unsigned revision,const std::string& configuration) {
    return "{\"revision\":"+std::to_string(revision)+",\"config\":"+configuration+"}";
}
std::string mailError(unsigned revision,const std::string& error) {
    std::string escaped;
    for(char c:error) {
        if(c=='"' || c=='\\') escaped+='\\';
        escaped+=(unsigned char)c<32?' ':c;
    }
    return "{\"revision\":"+std::to_string(revision)+",\"error\":\""+escaped+"\"}";
}

#ifdef PBZ_DLL
void read(HANDLE,U64 address,void* dest,size_t n) {
    size_t done=0;
    while(done<n) {
        MEMORY_BASIC_INFORMATION region{};
        check(VirtualQuery((void*)(address+done),&region,sizeof(region))!=0,"query image memory");
        if(region.State!=MEM_COMMIT || (region.Protect&(PAGE_NOACCESS|PAGE_GUARD))) throw std::runtime_error("Unreadable image memory");
        size_t count=std::min(n-done,(size_t)((U64)region.BaseAddress+region.RegionSize-address-done));
        if(!count) throw std::runtime_error("Invalid image region");
        std::memcpy((unsigned char*)dest+done,(void*)(address+done),count); done+=count;
    }
}
void write(HANDLE,U64 address,const void* data,size_t n) { std::memcpy((void*)address,data,n); }
BOOL protect(HANDLE,void* address,size_t n,DWORD flags,DWORD* old) { return VirtualProtect(address,n,flags,old); }
void* allocate(HANDLE,void* address,size_t n) { return VirtualAlloc(address,n,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); }
BOOL release(HANDLE,void* address) { return VirtualFree(address,0,MEM_RELEASE); }
#else
void read(HANDLE p,U64 address,void* dest,size_t n) { SIZE_T done=0; check(ReadProcessMemory(p,(void*)address,dest,n,&done)&&done==n,"read memory"); }
void write(HANDLE p,U64 address,const void* data,size_t n) { SIZE_T done=0; check(WriteProcessMemory(p,(void*)address,data,n,&done)&&done==n,"write memory"); }
BOOL protect(HANDLE p,void* address,size_t n,DWORD flags,DWORD* old) { return VirtualProtectEx(p,address,n,flags,old); }
void* allocate(HANDLE p,void* address,size_t n) { return VirtualAllocEx(p,address,n,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); }
BOOL release(HANDLE p,void* address) { return VirtualFreeEx(p,address,0,MEM_RELEASE); }
#endif
void patch(HANDLE p,U64 address,const Bytes& bytes) {
    DWORD old=0,unused=0; check(protect(p,(void*)address,bytes.size(),PAGE_EXECUTE_READWRITE,&old),"patch protect");
    try { write(p,address,bytes.data(),bytes.size()); }
    catch(...) { protect(p,(void*)address,bytes.size(),old,&unused); throw; }
    check(protect(p,(void*)address,bytes.size(),old,&unused),"restore protect");
    check(FlushInstructionCache(p,(void*)address,bytes.size()),"flush instructions");
}
void imm64(Bytes& b,U64 n) { for(int i=0;i<8;++i) b.push_back((unsigned char)(n>>(i*8))); }
void imm32(Bytes& b,int n) { for(int i=0;i<4;++i) b.push_back((unsigned char)((unsigned)n>>(i*8))); }
void rel32(Bytes& b,U64 from,U64 to) {
    auto d=(long long)to-(long long)from; if(d<INT32_MIN||d>INT32_MAX) throw std::runtime_error("rel32 out of range"); imm32(b,(int)d);
}
void absoluteJump(Bytes& b,U64 target) { b.insert(b.end(),{0xff,0x25,0,0,0,0}); imm64(b,target); }
U64 relativeCallTarget(U64 address,const Bytes& instruction) {
    if(instruction.size()!=5 || instruction[0]!=0xe8)
        throw std::runtime_error("Redirect is not a five-byte CALL rel32");
    int32_t displacement=0;
    std::memcpy(&displacement,instruction.data()+1,sizeof(displacement));
    const auto target=(long long)address+5+(long long)displacement;
    if(target<=0) throw std::runtime_error("CALL target is invalid");
    return (U64)target;
}
bool executableAddress(U64 address,MEMORY_BASIC_INFORMATION& region) {
    if(!address || !VirtualQuery((const void*)address,&region,sizeof(region)) ||
       region.State!=MEM_COMMIT || (region.Protect&(PAGE_NOACCESS|PAGE_GUARD))) return false;
    const DWORD protection=region.Protect&0xff;
    return protection==PAGE_EXECUTE || protection==PAGE_EXECUTE_READ ||
           protection==PAGE_EXECUTE_READWRITE || protection==PAGE_EXECUTE_WRITECOPY;
}
#include "signatures.hpp"
ImageView snapshotImage(HANDLE p,U64 base) {
    IMAGE_DOS_HEADER dos{}; read(p,base,&dos,sizeof(dos));
    if(dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew<=0 || dos.e_lfanew>0x100000) throw std::runtime_error("Invalid PE DOS header");
    IMAGE_NT_HEADERS64 nt{}; read(p,base+dos.e_lfanew,&nt,sizeof(nt));
    if(nt.Signature!=IMAGE_NT_SIGNATURE || nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64 ||
       nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC || nt.FileHeader.SizeOfOptionalHeader!=sizeof(IMAGE_OPTIONAL_HEADER64) ||
       !nt.FileHeader.NumberOfSections || nt.FileHeader.NumberOfSections>96 ||
       !nt.OptionalHeader.SizeOfImage || nt.OptionalHeader.SizeOfImage>1024*1024*1024)
        throw std::runtime_error("Unsupported PE image");
    ImageView image{Bytes(nt.OptionalHeader.SizeOfImage),base,{}};
    U64 table=dos.e_lfanew+24+nt.FileHeader.SizeOfOptionalHeader;
    if(table+nt.FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER)>nt.OptionalHeader.SizeOfHeaders) throw std::runtime_error("Invalid PE section table");
    for(unsigned i=0;i<nt.FileHeader.NumberOfSections;++i) {
        IMAGE_SECTION_HEADER s{}; read(p,base+table+i*sizeof(s),&s,sizeof(s));
        size_t size=s.Misc.VirtualSize;
        if(s.VirtualAddress>image.bytes.size() || size>image.bytes.size()-s.VirtualAddress) throw std::runtime_error("PE section exceeds image");
        if(!size || !(s.Characteristics&IMAGE_SCN_MEM_READ) || (s.Characteristics&IMAGE_SCN_MEM_DISCARDABLE)) continue;
        for(auto other:image.sections) if(s.VirtualAddress<other.begin+other.size && other.begin<s.VirtualAddress+size) throw std::runtime_error("Overlapping PE sections");
        read(p,base+s.VirtualAddress,image.bytes.data()+s.VirtualAddress,size);
        image.sections.push_back({s.VirtualAddress,size,s.Characteristics});
    }
    return image;
}
U64 allocateNear(HANDLE p,U64 callAddress) {
    // 64 KiB aligned allocations, all hooks and relocated operands must fit rel32.
    U64 center=callAddress&~U64(65535);
    for(U64 d=0x10000;d<0x70000000;d+=0x10000) {
        for(U64 addr:{center+d,center-d}) {
            auto v=allocate(p,(void*)addr,SLAB_SIZE);
            if(v) return (U64)v;
        }
    }
    throw std::runtime_error("No nearby allocation");
}
// Leaf trampoline: no foreign DLL, CRT or UE allocation ownership. Original argv untouched.
Bytes startStub(U64 slab,U64 target) {
    Bytes b={0x9c,0x48,0xff,0x05}; rel32(b,slab+8,slab+4096+8); // pushfq; inc qword [counter]
    b.push_back(0x9d); b.insert(b.end(),{0x48,0xba}); imm64(b,slab+4128); // popfq; mov rdx,FString*
    absoluteJump(b,target); return b;
}
Bytes loggerStub(U64 at,U64 ring,U64 original,const Bytes& stolen,bool captureAll=false) {
    // Preserve flags and every register touched. No calls, so no unwind/stack-alignment change.
    Bytes b={0x9c,0x50,0x51,0x52,0x56,0x57,0x41,0x51,0x41,0x52,0x41,0x53};
    std::vector<size_t> exits;
    auto jcc=[&](unsigned char op){ b.insert(b.end(),{0x0f,op}); exits.push_back(b.size()); imm32(b,0); };
    auto add=[&](std::initializer_list<unsigned char> v){b.insert(b.end(),v);};
    add({0x48,0x85,0xd2}); jcc(0x84); // test rdx
    add({0x8b,0x4a,0x08,0x83,0xf9,(unsigned char)(captureAll?1:5)}); jcc(0x8c);
    add({0x48,0x8b,0x32,0x48,0x85,0xf6}); jcc(0x84); // rsi=data
    if(!captureAll) {
        add({0x48,0xb8}); imm64(b,0x005a00420050005bULL); // UTF-16 "[PBZ"
        add({0x48,0x39,0x06}); jcc(0x85);
    }
    add({0xff,0xc9,0xb8,0xe8,0x03,0,0,0x39,0xc1,0x0f,0x47,0xc8}); // min(count-1,1000)
    add({0x49,0xbb}); imm64(b,ring);
    add({0xb8,1,0,0,0,0xf0,0x49,0x0f,0xc1,0x03}); // lock xadd [r11],rax
    add({0x4c,0x8d,0x50,0x01,0x25,0xff,0,0,0,0x48,0xc1,0xe0,0x0b}); // seq=old+1; slot=(old&255)*2048
    add({0x49,0x8d,0xbc,0x03}); imm32(b,4096); // rdi=ring+4096+slot (slab+8192)
    add({0x49,0x89,0xf9,0x48,0xc7,0x07,0,0,0,0,0x89,0x4f,0x08,0x48,0x83,0xc7,0x10,0xfc,0xf3,0x66,0xa5});
    add({0x4d,0x87,0x11}); // xchg [r9],r10 publishes complete record
    size_t end=b.size(); for(auto i:exits) { int d=(int)(end-i-4); std::memcpy(b.data()+i,&d,4); }
    add({0x41,0x5b,0x41,0x5a,0x41,0x59,0x5f,0x5e,0x5a,0x59,0x58,0x9d});
    // Relocate the exact seven-byte cmp byte [rip+disp32],imm8; following jcc stays original.
    int oldDisp; std::memcpy(&oldDisp,stolen.data()+2,4);
    U64 operand=original+7+oldDisp;
    b.insert(b.end(),{0x80,0x3d}); rel32(b,at+b.size()+5,operand); b.push_back(stolen[6]);
    Bytes j={0xe9}; rel32(j,at+b.size()+5,original+7); b.insert(b.end(),j.begin(),j.end()); return b;
}
struct Patch { U64 address; Bytes old; };
struct Installed { U64 slab=0; std::vector<Patch> patches; };
struct ValidationCalls {
    std::array<Bytes,5> instructions;
    std::array<U64,5> targets{};
};
ValidationCalls captureValidationCalls(HANDLE p,U64 base,const ImageView& image,const HookSites& sites) {
    ValidationCalls result{};
    for(size_t i=0;i<sites.validationCalls.size();++i) {
        const auto at=sites.validationCalls[i];
        if(!at) throw std::runtime_error("Missing script validation call site; index="+std::to_string(i));
        const U64 address=base+at;
        const Bytes snapshot(image.bytes.begin()+at,image.bytes.begin()+at+5);
        const U64 expectedTarget=base+(i==4?sites.validateText:sites.validateBytes);
        if(relativeCallTarget(address,snapshot)!=expectedTarget)
            throw std::runtime_error("Validation call snapshot target disagrees with resolved validator; index="+std::to_string(i));
        result.instructions[i].resize(5);
        read(p,address,result.instructions[i].data(),result.instructions[i].size());
        result.targets[i]=relativeCallTarget(address,result.instructions[i]);
        MEMORY_BASIC_INFORMATION region{};
        if(!executableAddress(result.targets[i],region))
            throw std::runtime_error("Validation CALL target is not committed executable memory; index="+std::to_string(i));
    }
    return result;
}
Installed install(HANDLE p,U64 base,const ImageView& image,const HookSites& sites,
                  const ValidationCalls& validationCalls,const std::array<U64,5>& validationHooks,
                  const std::wstring& module) {
    Installed state;
    // The name lies between the FString at +4128 and the logger ring at +8192.
    if(module.empty() || (module.size()+1)*sizeof(wchar_t)>8192-4160) throw std::runtime_error("Invalid start module name");
    const auto& loggers=sites.loggers;
    std::array<Bytes,3> signatures;
    for(int i=0;i<3;++i) signatures[i]=Bytes(image.bytes.begin()+loggers[i],image.bytes.begin()+loggers[i]+7);
    const Bytes originalCall(image.bytes.begin()+sites.call,image.bytes.begin()+sites.call+5);
    const U64 callAddress=base+sites.call;
    const U64 originalTarget=relativeCallTarget(callAddress,originalCall);
    if(originalTarget!=base+sites.start)
        throw std::runtime_error("MainStart CALL target disagrees with resolved thunk");
    Bytes activeCall(5);
    read(p,callAddress,activeCall.data(),activeCall.size());
    const U64 activeTarget=relativeCallTarget(callAddress,activeCall);
    MEMORY_BASIC_INFORMATION targetRegion{};
    if(!executableAddress(activeTarget,targetRegion))
        throw std::runtime_error("MainStart CALL target is not committed executable memory");
    auto verify=[&](const char* label,U64 addr,const Bytes& expected) {
        Bytes got(expected.size());
        read(p,addr,got.data(),got.size());
        if(got!=expected)
            throw std::runtime_error(std::string("Instruction signature mismatch; site=")+label);
    };
    verify("MainStart thunk",base+sites.start,
           {0x48,0x8b,0x09,0x48,0x8b,0x01,0x48,0xff,0x20});
    if(!sites.validateBytes || !sites.validateText)
        throw std::runtime_error("Missing script validation sites");
    for(size_t i=0;i<validationHooks.size();++i)
        if(!validationHooks[i] || !validationCalls.targets[i] || validationCalls.instructions[i].size()!=5)
            throw std::runtime_error("Missing per-call validation chain; index="+std::to_string(i));
    for(size_t i=0;i<3;++i) {
        auto label="Logger "+std::to_string(i);
        verify(label.c_str(),base+loggers[i],signatures[i]);
    }
    state.slab=allocateNear(p,base+sites.call);
    try {
        Bytes blob(3072); auto stub=startStub(state.slab,activeTarget); std::copy(stub.begin(),stub.end(),blob.begin());
        // One adapter per call site preserves each pre-existing validation hook chain.
        for(size_t i=0;i<validationHooks.size();++i) {
            Bytes gate; absoluteJump(gate,validationHooks[i]);
            std::copy(gate.begin(),gate.end(),blob.begin()+2048+i*32);
        }
        for(int i=0;i<3;++i) {
            // PuerTS startup errors occur before bootstrap can add our prefix.
            auto logger=loggerStub(state.slab+256+i*512,state.slab+4096,base+loggers[i],signatures[i],i!=0);
            if(logger.size()>512) throw std::runtime_error("Logger stub overflow");
            std::copy(logger.begin(),logger.end(),blob.begin()+256+i*512);
        }
        write(p,state.slab,blob.data(),blob.size());
        const int length=(int)module.size()+1;
        struct String { U64 data; int count; int capacity; } name={state.slab+4160,length,length};
        write(p,state.slab+4128,&name,sizeof(name)); write(p,state.slab+4160,module.c_str(),length*sizeof(wchar_t));
        // Executable code is RX; counters, FString and bounded ring are on RW pages.
        DWORD ignored; check(protect(p,(void*)state.slab,4096,PAGE_EXECUTE_READ,&ignored),"stub RX");
        check(FlushInstructionCache(p,(void*)state.slab,4096),"flush stubs");
        // Prove every rel32 branch fits before changing any game instruction.
        Bytes call={0xe8}; rel32(call,base+sites.call+5,state.slab);
        std::array<Bytes,3> hooks;
        for(int i=0;i<3;++i) { hooks[i]={0xe9}; rel32(hooks[i],base+loggers[i]+5,state.slab+256+i*512); hooks[i].insert(hooks[i].end(),{0x90,0x90}); }
        std::array<Bytes,5> validators;
        for(size_t i=0;i<validators.size();++i) {
            validators[i]={0xe8}; rel32(validators[i],base+sites.validationCalls[i]+5,state.slab+2048+i*32);
        }
        for(size_t i=0;i<validators.size();++i) {
            auto at=sites.validationCalls[i];
            Bytes live(5);
            read(p,base+at,live.data(),live.size());
            if(live!=validationCalls.instructions[i])
                throw std::runtime_error("Validation CALL changed during hook install; refusing to overwrite another hook; index="+std::to_string(i));
            state.patches.push_back({base+at,validationCalls.instructions[i]});
            patch(p,base+at,validators[i]);
        }
        for(int i=0;i<3;++i) {
            state.patches.push_back({base+loggers[i],signatures[i]});
            patch(p,base+loggers[i],hooks[i]);
        }
        Bytes liveCall(5);
        read(p,callAddress,liveCall.data(),liveCall.size());
        if(liveCall!=activeCall)
            throw std::runtime_error("MainStart CALL changed during hook install; refusing to overwrite another hook");
        state.patches.push_back({callAddress,activeCall});
        patch(p,callAddress,call);
        return state;
    } catch(...) {
        bool restored=true; for(auto it=state.patches.rbegin();it!=state.patches.rend();++it) try{patch(p,it->address,it->old);}catch(...){restored=false;}
        if(restored) release(p,(void*)state.slab);
        throw;
    }
}
void drain(HANDLE p,U64 slab,U64& next) {
    U64 count=0; read(p,slab+4096,&count,8);
    if(count>next+256) { log("log-overflow dropped="+std::to_string(count-next-256)); next=count-256; }
    while(next<count) {
        std::array<unsigned char,2048> b{}; U64 addr=slab+8192+(next%256)*2048;
        read(p,addr,b.data(),b.size()); U64 seq=0,again=0; unsigned len=0;
        std::memcpy(&seq,b.data(),8); std::memcpy(&len,b.data()+8,4); read(p,addr,&again,8);
        if(seq!=next+1 || again!=seq) break;
        if(len<=1000) log(utf8(std::wstring((wchar_t*)(b.data()+16),len)));
        ++next;
    }
}
