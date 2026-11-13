// Exercise the actual machine-code generators in an isolated native process.
#include "../src/core.hpp"
#include "../src/mod-validation.hpp"
#include <thread>
#include <cassert>
struct FString { const wchar_t* data; int count; int capacity; };
void* expectedContext; void* expectedArgv;
void capture(void* context,const FString* name,void* argv) {
    assert(context==expectedContext && argv==expectedArgv);
    assert(std::wstring(name->data)==L"PBZModLoader/bootstrap");
    assert(name->count==22 && name->capacity==22);
}
int main() {
    {
        const U64 call=0x100000000ULL;
        const Bytes backward={0xe8,0xfb,0xff,0xff,0xff};
        const Bytes forward={0xe8,0x10,0x00,0x00,0x00};
        assert(relativeCallTarget(call,backward)==call);
        assert(relativeCallTarget(call,forward)==call+0x15);
        bool rejected=false;
        try { (void)relativeCallTarget(call,Bytes{0x90,0,0,0,0}); }
        catch(const std::exception&) { rejected=true; }
        assert(rejected);
    }
    HANDLE process=GetCurrentProcess();
    auto slab=(U64)VirtualAlloc(nullptr,SLAB_SIZE,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE); assert(slab);
    auto start=startStub(slab,(U64)&capture); write(process,slab,start.data(),start.size());
    const wchar_t text[]=L"PBZModLoader/bootstrap";
    FString name={(wchar_t*)(slab+4160),22,22}; write(process,slab+4128,&name,sizeof(name)); write(process,slab+4160,text,sizeof(text));
    U64 original=slab+2048, operand=slab+4208;
    Bytes stolen={0x80,0x3d}; rel32(stolen,original+7,operand); stolen.push_back(5);
    // Original cmp followed by setae al; ret. The relocated cmp must preserve flags.
    Bytes fake=stolen; fake.insert(fake.end(),{0x0f,0x93,0xc0,0xc3}); write(process,original,fake.data(),fake.size());
    *(unsigned char*)operand=5;
    auto logger=loggerStub(slab+256,slab+4096,original,stolen); write(process,slab+256,logger.data(),logger.size());
    auto diagnostics=loggerStub(slab+768,slab+4096,original,stolen,true); write(process,slab+768,diagnostics.data(),diagnostics.size());
    DWORD old; assert(VirtualProtect((void*)slab,4096,PAGE_EXECUTE_READ,&old)); FlushInstructionCache(process,(void*)slab,4096);
    expectedContext=(void*)0x1234; expectedArgv=(void*)0x5678;
    ((void(*)(void*,FString*,void*))slab)(expectedContext,nullptr,expectedArgv);
    assert(*(U64*)(slab+4104)==1);
    auto emit=(unsigned char(*)(void*,const FString*))(slab+256);
    const wchar_t message[]=L"[PBZMOD] native stub test"; FString msg={message,(int)std::size(message),(int)std::size(message)};
    assert(emit(nullptr,&msg)==1); assert(*(U64*)(slab+4096)==1);
    assert(*(U64*)(slab+8192)==1); assert(std::wstring((wchar_t*)(slab+8192+16),std::size(message)-1)==message);
    const wchar_t other[]=L"unrelated"; FString skip={other,10,10}; emit(nullptr,&skip); emit(nullptr,nullptr); assert(*(U64*)(slab+4096)==1);
    std::wstring longMessage=L"[PBZMOD]"+std::wstring(3000,L'x'); FString longMsg={longMessage.c_str(),(int)longMessage.size()+1,(int)longMessage.size()+1}; emit(nullptr,&longMsg);
    assert(*(unsigned*)(slab+8192+2048+8)==1000);
    std::vector<std::thread> workers; for(int i=0;i<8;++i) workers.emplace_back([&]{for(int j=0;j<16;++j) assert(emit(nullptr,&msg)==1);});
    for(auto& t:workers)t.join(); assert(*(U64*)(slab+4096)==130);
    for(int i=0;i<130;++i) assert(*(U64*)(slab+8192+i*2048)==(U64)i+1);
    for(int i=0;i<300;++i) emit(nullptr,&msg);
    assert(*(U64*)(slab+4096)==430);
    for(U64 i=174;i<430;++i) assert(*(U64*)(slab+8192+(i%256)*2048)==i+1);
    auto emitDiagnostic=(unsigned char(*)(void*,const FString*))(slab+768);
    emitDiagnostic(nullptr,&skip);
    const wchar_t shortText[]=L"!"; FString shortMsg={shortText,2,2}; emitDiagnostic(nullptr,&shortMsg);
    emitDiagnostic(nullptr,nullptr);
    assert(*(U64*)(slab+4096)==432);
    assert(std::wstring((wchar_t*)(slab+8192+(430%256)*2048+16),9)==L"unrelated");
    assert(*(unsigned*)(slab+8192+(431%256)*2048+8)==1);
    VirtualFree((void*)slab,0,MEM_RELEASE);
    auto temp=fs::temp_directory_path()/(L"pbz-loader-test-"+std::to_wstring(GetCurrentProcessId()));
    assert(fs::create_directory(temp)); fs::create_directories(temp/L"mods/a");
    {
        auto root=temp/L"validation";
        fs::create_directories(root/L"mods/test");
        const std::string code="module.exports = '\xe4\xb8\xad\xe6\x96\x87';";
        { std::ofstream f(root/L"mods/test/main.js",std::ios::binary); f<<code; }
        { std::ofstream f(root/L"manager.js",std::ios::binary); f<<code; }
        auto string=[](const std::wstring& value) { return GameString{value.c_str(),(int)value.size()+1,(int)value.size()+1}; };
        const auto base=fs::canonical(root).generic_wstring();
        std::wstring path=base+L"/mods/test/main.js";
        auto name=string(path);
        GameBytes bytes{(const unsigned char*)code.data(),(int)code.size(),(int)code.size()};
        assert(trustedModBytes(root,&name,&bytes));
        std::wstring raw=L"module.exports = '\u4e2d\u6587';";
        auto source=string(raw); assert(trustedModText(root,&name,&source));
        std::wstring wrapped=L"(function (exports, require, module, __filename, __dirname) { "+raw+L"\n});";
        source=string(wrapped); assert(trustedModText(root,&name,&source));
        wrapped+=L"evil()"; source=string(wrapped); assert(!trustedModText(root,&name,&source));
        bytes.count--; assert(!trustedModBytes(root,&name,&bytes)); bytes.count++;
        // Hot reload spells the root differently per revision: the same file, the same trust.
        std::wstring alias=path;
        for(size_t i=0;i<base.size();++i) if(alias[i]>=L'a' && alias[i]<=L'z') { alias[i]-=32; break; }
        alias[base.size()+1]=L'M';
        auto aliased=string(alias); assert(trustedModBytes(root,&aliased,&bytes));
        for(const auto& denied:{std::wstring(L"project/mainstart.js"),base+L"/mods/../manager.js",base+L"/mods/test/../../manager.js",
            base+L"/manager.js",base+L"X/mods/test/main.js",base+L"/mods/test/main.js:stream",base+L"/mods//test/main.js"}) {
            auto rejected=string(denied);
            assert(!trustedModBytes(root,&rejected,&bytes));
        }
        assert(!trustedModBytes(root,nullptr,&bytes));
        source.count=0; assert(!trustedModText(root,&name,&source));
        std::cout<<"PASS MOD validation: exact bytes, UTF-8, CommonJS wrapper, spelling of the root, paths outside mods, traversal and content mismatch\n";
    }
    {
        for(const auto& allowed:{L"../../../ProjectPBZ/Content/JavaScript/UI/Widget/Foundation/WeaponAdvancdNumricEntry.js",
            L"../../../ProjectPBZ/Content/JavaScript/Mods/data.json",L"T:\\Games\\ProjectPBZ\\Content\\JavaScript\\MainStart.js"})
            assert(gameScriptPath(allowed));
        for(const auto& denied:{L"project/mainstart.js",L"../../../ProjectPBZ/Content/JavaScript/../../escape.js",
            L"../../../ProjectPBZ/Content/JavaScript/main.ts",L"../../../ProjectPBZ/Content/JavaScript/",
            L"../../../ProjectPBZ/PBZModLoader/mods/a/main.js",L"../../../ProjectPBZ/Content/JavaScript/a//b.js"})
            assert(!gameScriptPath(denied));
        std::string memory(40,'x');
        GameBytes target{(const unsigned char*)memory.data(),40,40};
        assert(replaceBytes(&target,"short") && target.count==5 && memory.substr(0,5)=="short");
        assert(!replaceBytes(&target,std::string(41,'y')) && target.count==5);
        assert(!replaceBytes(nullptr,"x"));
        assert(mailMessage(3,"{}")=="{\"revision\":3,\"config\":{}}");
        assert(mailError(4,"bad \"quote\"\n")=="{\"revision\":4,\"error\":\"bad \\\"quote\\\" \"}");
        std::cout<<"PASS changed game script paths, replacing a script in its own memory, mail messages\n";
    }
    { std::ofstream f(temp/L"mods/a/main.js"); f<<"module.exports={};"; }
    auto iniTest=[&](const std::string& content,bool expected) {
        { std::ofstream f(temp/L"mods.ini"); f<<content; }
        // Invalidate Windows INI cache between fixture writes.
        WritePrivateProfileStringW(nullptr,nullptr,nullptr,(temp/L"mods.ini").c_str());
        bool accepted=false; try { config(temp); accepted=true; } catch(const std::exception&) {}
        assert(accepted==expected);
    };
    const std::string prefix="[Loader]\nVersion=1\nCount=1\n[Mod.0]\nId=a\n";
    iniTest(prefix+"Enabled=1\nEntry=mods/a/main.js\n",true);
    iniTest(prefix+"Enabled=1\nEntry=mods/missing/main.js\n",false);
    iniTest(prefix+"Enabled=0\nEntry=mods/missing/main.js\n",true);
    iniTest(prefix+"Enabled=1\nEntry=../escape.js\n",false);
    iniTest(prefix+"Enabled=1\nEntry=mods/a/main.ts\n",false);
    iniTest(prefix+"Enabled=2\nEntry=mods/a/main.js\n",false);
    iniTest("[Loader]\nVersion=1\nCount=2\n[Mod.0]\nId=a\nEnabled=1\nEntry=mods/a/main.js\n[Mod.1]\nId=a\nEnabled=0\nEntry=mods/a/main.js\n",false);
    const std::string automatic="[Loader]\nVersion=1\n";
    iniTest(automatic,true);
    assert(config(temp).find("\"id\":\"a\",\"enabled\":true")!=std::string::npos);
    fs::create_directories(temp/L"mods/z");
    fs::create_directories(temp/L"mods/helper/nested");
    { std::ofstream f(temp/L"mods/z/main.js"); f<<"module.exports={};"; }
    { std::ofstream f(temp/L"mods/helper/nested/main.js"); f<<"module.exports={};"; }
    { std::ofstream f(temp/L"mods/loose.js"); f<<"module.exports={};"; }
    auto generated=config(temp);
    assert(generated.find("\"id\":\"a\"")<generated.find("\"id\":\"z\""));
    assert(generated.find("helper")==std::string::npos && generated.find("loose")==std::string::npos);
    iniTest(automatic+"[Mods]\na=0\nz=1\nabsent=0\n",true);
    assert(config(temp).find("\"id\":\"a\",\"enabled\":false")!=std::string::npos);
    iniTest(automatic+"[Mods]\na=2\n",false);
    iniTest(prefix+"Enabled=0\nEntry=mods/a/main.js\n",true);
    generated=config(temp);
    assert(generated.find("\"id\":\"a\",\"enabled\":false")!=std::string::npos);
    assert(generated.find("\"id\":\"a\"",generated.find("\"id\":\"a\"")+1)==std::string::npos);
    assert(generated.find("\"id\":\"z\"")!=std::string::npos);
    iniTest("[Loader]\nVersion=1\nCount=1\n[Mod.0]\nId=alias\nEnabled=0\nEntry=mods/a/main.js\n",true);
    assert(config(temp).find("\"id\":\"a\"")==std::string::npos);
    iniTest(prefix+"Enabled=1\nEntry=mods/a/main.js\n[Mods]\na=0\n",true);
    assert(config(temp).find("\"id\":\"a\",\"enabled\":false")!=std::string::npos);
    fs::remove(temp/L"mods/z/main.js");
    assert(config(temp).find("\"id\":\"z\"")==std::string::npos);
    // No mods.ini at all: every discovered MOD loads.
    fs::remove(temp/L"mods.ini");
    assert(config(temp).find("\"id\":\"a\",\"enabled\":true")!=std::string::npos);
    { std::ofstream f(temp/L"mods.ini"); f<<automatic; }
    WritePrivateProfileStringW(nullptr,nullptr,nullptr,(temp/L"mods.ini").c_str());
    assert(config(temp).find("\"root\":\""+utf8(fs::absolute(temp).generic_wstring())+"\"")!=std::string::npos);
    // JavaScript wins over a TypeScript source; TypeScript alone is reported, not compiled.
    { std::ofstream f(temp/L"mods/a/main.ts"); f<<"export const answer: number = 1;"; }
    assert(config(temp).find("\"id\":\"a\",\"enabled\":true,\"entry\":\"mods/a/main.js\"")!=std::string::npos);
    fs::remove(temp/L"mods/a/main.js");
    generated=config(temp);
    assert(generated.find("\"id\":\"a\",\"enabled\":false,\"entry\":\"mods/a/main.js\",\"note\":\"TypeScript source without main.js\"")!=std::string::npos);
    { std::ofstream f(temp/L"mods/a/main.js"); f<<"module.exports={};"; }
    fs::remove(temp/L"mods/a/main.ts");
    std::cout<<"PASS optional mods.ini, JavaScript before TypeScript, TypeScript alone reported\n";
    fs::remove_all(temp/L"mods");
    iniTest(automatic,true);
    assert(config(temp).find("\"mods\":[]")!=std::string::npos);
    fs::remove_all(temp);
    auto layout=fs::temp_directory_path()/(L"pbz-layout-test-"+std::to_wstring(GetCurrentProcessId()));
    fs::create_directories(layout/L"ProjectPBZ/Content");
    for(const auto& relative:{L"platform/steam/PBZ.exe",L"platform/wegame/PBZ.exe",L"ProjectPBZ/Binaries/Win64/PBZ.exe",L"PBZ.exe"})
        assert(findProject(layout/relative)==fs::canonical(layout/L"ProjectPBZ"));
    fs::remove_all(layout/L"ProjectPBZ/Content");
    bool missing=false; try { findProject(layout/L"platform/wegame/PBZ.exe"); } catch(const std::exception&) { missing=true; } assert(missing);
    fs::remove_all(layout);
    std::cout<<"PASS platform-independent project discovery and missing project rejection\n";
    {
        auto folder=fs::temp_directory_path()/(L"pbz-start-file-test-"+std::to_wstring(GetCurrentProcessId()));
        auto file=folder/L"bootstrap.js";
        fs::create_directories(folder);
        assert(!usableStartFile(file,100));
        { std::ofstream f(file,std::ios::binary); f<<std::string(100,' '); }
        assert(usableStartFile(file,100) && !usableStartFile(file,101));
        fs::remove(file); fs::create_directories(file);
        assert(!usableStartFile(file,0));
        fs::remove_all(folder);
        // The module name the game asks for and the file the package ships must be the same script.
        assert(lowerSlashes(std::wstring(L"/content/javascript/")+START_FILE_MODULE+L".js")==lowerSlashes(std::wstring(L"/")+START_FILE_PATH));
        std::cout<<"PASS start file: missing, too small, large enough, a folder instead of a file, name and path agree\n";
    }
    std::cout<<"PASS native redirect, argv, counter, relocated flags, filtering, bounds, concurrency, ring wrap\n";
    std::cout<<"PASS native config: valid, missing, disabled, traversal, invalid switch, duplicate ID\n";
    std::cout<<"PASS automatic discovery: sorting, dependencies ignored, switches, legacy merge, removal, empty directory\n";
}
