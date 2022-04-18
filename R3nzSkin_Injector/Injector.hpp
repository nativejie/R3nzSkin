#pragma once

#include <Windows.h>
#include <chrono>
#include <cinttypes>
#include <string>
#include <vector>

using namespace std::chrono_literals;
// vector是C++标准模板库中的部分内容，它是一个多功能的，能够操作多种数据结构和算法的模板类和函数库。vector之所以被认为是一个容器，是因为它能够像容器一样存放各种类型的对象，简单地说，vector是一个能够存放任意类型的动态数组，能够增加和压缩数据。
// unit32_t  typedef 定义的无符号 int 型宏定义
using proclist_t = std::vector<std::uint32_t>;

struct NtCreateThreadExBuffer {
    SIZE_T Size;
    SIZE_T Unknown1;
    SIZE_T Unknown2;
    PULONG Unknown3;
    SIZE_T Unknown4;
    SIZE_T Unknown5;
    SIZE_T Unknown6;
    PULONG Unknown7;
    SIZE_T Unknown8;
};

#pragma comment(lib, "ntdll.lib")
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, SIZE_T, SIZE_T, SIZE_T, LPVOID);

class Injector {
public:
	static proclist_t WINAPI findProcesses(const std::wstring name) noexcept;
	static bool WINAPI isInjected(const std::uint32_t pid) noexcept;
	static bool WINAPI inject(const std::uint32_t pid) noexcept;
	static void WINAPI enableDebugPrivilege() noexcept;
    static std::string randomString(std::uint32_t size) noexcept;
    static void renameExe() noexcept;
	static void run() noexcept;
};
