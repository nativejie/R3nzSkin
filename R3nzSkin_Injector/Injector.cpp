#include <Windows.h>
#include <cstdlib>
#include <fstream>
#include <psapi.h>
#include <string>
#include <thread>
#include <tlhelp32.h>

#include "Injector.hpp"
#include "R3nzUI.hpp"

/**
 * @brief 获取一个进程名
 * 
 * @param name 进程名称
 * @return proclist_t 查找到的进程list
 */
proclist_t WINAPI Injector::findProcesses(const std::wstring name) noexcept
{
	// 可以通过获取进程信息为指定的进程、进程使用的堆[HEAP]、模块[MODULE]、线程建立一个快照。说到底，可以获取系统中正在运行的进程信息，线程信息，等
	// process_snap 快照变量
	// CreateToolhelp32Snapshot 参数1 用来指定“快照”中需要返回的对象 2. /一个进程ID号
	auto process_snap{ ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
	proclist_t list;

	if (process_snap == INVALID_HANDLE_VALUE)
		return list;

	// 用来存放快照进程信息的一个结构体
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	// process32First是一个进程获取函数，当我们利用函数CreateToolhelp32Snapshot()获得当前运行进程的快照后，我们可以利用process32First函数来获得第一个进程的句柄
	if (::Process32First(process_snap, &pe32)) {
		// szExeFile 进程的可执行文件的名称
		if (pe32.szExeFile == name)
			// 在vector类中作用为在vector尾部加入一个数据
			list.push_back(pe32.th32ProcessID);

		// 检索关于记录在系统快照中的下一个进程的信息。 返回BOOL
		while (::Process32Next(process_snap, &pe32)) {
			if (pe32.szExeFile == name)
				list.push_back(pe32.th32ProcessID);
		}
	}
	// 关闭一个内核对象。其中包括文件、文件映射、进程、线程、安全和同步对象等
	::CloseHandle(process_snap);
	return list;
}

/**
 * @brief 判断是否注入成功
 * 
 * @param pid 游戏进程ID
 * @return true 
 * @return false 
 */
bool WINAPI Injector::isInjected(const std::uint32_t pid) noexcept
{
	// 函数用来打开一个已存在的进程对象，并返回进程的句柄 wiki: https://baike.baidu.com/item/OpenProcess/9511184?fr=aladdin
	// PROCESS_QUERY_INFORMATION: 获取进程的令牌、退出码和优先级等信息
	// PROCESS_VM_READ: 使用ReadProcessMemory函数在进程中读取内存
	// 参数二: 否继承句柄
	auto hProcess{ ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) };

	if (NULL == hProcess)
		return false;
	// 是 DLL 的基地址 wiki: https://stackoverflow.com/questions/9545732/what-is-hmodule
	HMODULE hMods[1024];
	// 双字节值
	DWORD cbNeeded;

	// 获取指定进程中每个模块的句柄。
	// 参数2：接收模块句柄列表的数组。
	// 参数3：lphModule数组的大小，以字节为单位。
	// 参数4：在lphModule数组中存储所有模块句柄所需的字节数。
	if (::K32EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		// 0U 无符号整型
		for (auto i{ 0u }; i < (cbNeeded / sizeof(HMODULE)); ++i) {
			TCHAR szModName[MAX_PATH];
			// 检索指定模块的基本名称。
			if (::K32GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
				// strcmp, wcscmp一样都是比较字符串的指针函数原型i
				if (::wcscmp(szModName, L"R3nzSkin.dll") == 0) {
					::CloseHandle(hProcess);
					return true;
				}
			}
		}
	}
	::CloseHandle(hProcess);
	return false;
}

/**
 * @brief 注入
 * 
 * @param pid 游戏PID
 * @return true 
 * @return false 
 */
bool WINAPI Injector::inject(const std::uint32_t pid) noexcept
{
	// 远程线程注入对象
	NtCreateThreadExBuffer ntbuffer;

	//  void *memset(void *str, int c, size_t n) 复制字符 c（一个无符号字符）到参数 str 所指向的字符串的前 n 个字符。
	::memset(&ntbuffer, 0, sizeof(NtCreateThreadExBuffer));
	DWORD temp1{ 0 };
	DWORD temp2{ 0 };

	// 远程注入固定参数
	ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntbuffer.Unknown1 = 0x10003;
	ntbuffer.Unknown2 = 0x8;
	ntbuffer.Unknown3 = static_cast<PULONG>(&temp1);
	ntbuffer.Unknown4 = 0;
	ntbuffer.Unknown5 = 0x10004;
	ntbuffer.Unknown6 = 4;
	ntbuffer.Unknown7 = static_cast<PULONG>(&temp2);
	ntbuffer.Unknown8 = 0;

	// 当前目录
	TCHAR current_dir[MAX_PATH];
	// 获取当前目录
	::GetCurrentDirectoryW(MAX_PATH, current_dir);
	// 获取所有权限
	const auto handle{ ::OpenProcess(PROCESS_ALL_ACCESS, false, pid) };

	if (!handle || handle == INVALID_HANDLE_VALUE)
		return false;

	FILETIME ft;
	SYSTEMTIME st;
	::GetSystemTime(&st); // 检索系统定时信息。在多处理器系统中，返回的值是所有处理器的指定时间的总和。
	::SystemTimeToFileTime(&st, &ft); // 将系统时间转换为文件时间格式。系统时间基于UTC(协调世界时)。
	FILETIME create, exit, kernel, user;
	::GetProcessTimes(handle, &create, &exit, &kernel, &user); // 检索指定进程的计时信息。 create 进程的创建时间。 exit 进程的退出时间。 kernel 进程在内核模式下执行的时间量 user 进程在用户模式下执行的时间量

	const auto delta{ 10 - static_cast<std::int32_t>((*reinterpret_cast<std::uint64_t*>(&ft) - *reinterpret_cast<std::uint64_t*>(&create.dwLowDateTime)) / 10000000U) };

	if (delta > 0)
		std::this_thread::sleep_for(std::chrono::seconds(delta));

	// DLL 路径
	const auto dll_path{ std::wstring(current_dir) + L"\\R3nzSkin.dll" };

	// 是从硬盘到内存，其实所谓的流缓冲就是内存空间 判断有没有该文件
	if (auto f{ std::ifstream(dll_path) }; !f.is_open()) {
		MessageBox(nullptr, L"R3nzSkin.dll file could not be found.\nTry reinstalling the cheat.", L"R3nzSkin", MB_ICONERROR | MB_OK);
		::CloseHandle(handle);
		return false;
	}

	// VirtualAllocEx 在指定进程的虚拟地址空间内保留、提交或更改内存区域的状态。该函数将其分配的内存初始化为零
	// wchar_t数据类型一般为16位或32位，但不同的C或C++库有不同的规定，如GNU Libc规定wchar_t为32位，总之，wchar_t所能表示的字符数远超char型。
	// 参数2：为要分配的页面区域指定所需起始地址的指针   参数3：要分配的内存区域的大小，以字节为单位  
	// 参数4：MEM_COMMIT 为指定的保留内存页面分配内存费用（来自内存的整体大小和磁盘上的页面文件）。该函数还保证当调用者稍后最初访问内存时，内容将为零。除非/直到实际访问虚拟地址，否则不会分配实际的物理页面。
	// MEM_RESERVE 保留进程的虚拟地址空间范围，而不在内存或磁盘上的页面文件中分配任何实际物理存储。
	// 参数5：PAGE_READWRITE 要分配的页面区域的内存保护。如果页面正在提交，您可以指定任何一个 内存保护常量
	const auto dll_path_remote{ ::VirtualAllocEx(handle, nullptr, (dll_path.size() + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

	if (!dll_path_remote) {
		::CloseHandle(handle);
		return false;
	}

	// 此函数能写入某一进程的内存区域（直接写入会出Access Violation错误），故需此函数入口区必须可以访问，否则操作将失败
	if (!::WriteProcessMemory(handle, dll_path_remote, dll_path.data(), (dll_path.size() + 1) * sizeof(wchar_t), nullptr)) {
		// VirtualFreeEx即为目标进程的句柄，可在其它进程中释放申请的虚拟内存空间
		::VirtualFreeEx(handle, dll_path_remote, 0u, MEM_RELEASE);
		::CloseHandle(handle);
		return false;
	}

	HANDLE thread;
	// 参数1：线程  2：线程权限 3. ObjectAttributes 4. 进程handle 5：参数
	// GetModuleHandle 功能是获取一个应用程序或动态链接库的模块句柄
	// GetProcAddress 功能是检索指定的动态链接库(DLL)中的输出库函数地址
	NtCreateThreadEx(&thread, GENERIC_ALL, NULL, handle, reinterpret_cast<LPTHREAD_START_ROUTINE>(::GetProcAddress(::GetModuleHandle(L"kernel32.dll"), "LoadLibraryW")), dll_path_remote, FALSE, NULL, NULL, NULL, &ntbuffer);

	if (!thread || thread == INVALID_HANDLE_VALUE) {
		// 释放
		::VirtualFreeEx(handle, dll_path_remote, 0u, MEM_RELEASE);
		::CloseHandle(handle);
		return false;
	}

	// 等待，直到指定对象处于有信号状态或超时间隔过去。使用WaitForSingleObjectEx函数进入alertable等待状态。要等待多个对象，请使用WaitForMultipleObjects。
	::WaitForSingleObject(thread, INFINITE);
	::CloseHandle(thread);
	::VirtualFreeEx(handle, dll_path_remote, 0u, MEM_RELEASE);
	::CloseHandle(handle);
	return true;
}

/**
 * @brief 启用调试
 * 
 */
void WINAPI Injector::enableDebugPrivilege() noexcept
{
	HANDLE token;

	if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		LUID value;
		if (::LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &value)) {
			TOKEN_PRIVILEGES tp;
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = value;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (::AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL))
				::CloseHandle(token);
		}
	}
}

std::string Injector::randomString(std::uint32_t size) noexcept
{
	static const char alphanum[]{ "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" };
	std::string tmp_s;
	tmp_s.reserve(size);

	for (auto i{ 0u }; i < size; ++i)
		tmp_s += alphanum[std::rand() % (sizeof(alphanum) - 1)];

	return tmp_s;
}

void Injector::renameExe() noexcept
{
	char szExeFileName[MAX_PATH];
	GetModuleFileNameA(nullptr, szExeFileName, MAX_PATH);

	const auto path{ std::string(szExeFileName) };
	const auto exe{ path.substr(path.find_last_of("\\") + 1, path.size()) };
	const auto newName{ randomString(std::rand() % (10 - 7 + 1) + 7) + ".exe" };

	rename(exe.c_str(), newName.c_str());
}

void Injector::run() noexcept
{
	enableDebugPrivilege();

	while (true) {
		// 查找LOL进程
		const auto& league_client_processes{ Injector::findProcesses(L"LeagueClient.exe") };
		const auto& league_processes{ Injector::findProcesses(L"League of Legends.exe") };

		R3nzSkinInjector::gameState = (league_processes.size() > 0) ? true : false;
		R3nzSkinInjector::clientState = (league_client_processes.size() > 0) ? true : false;

		// 开始注入
		for (auto& pid : league_processes) {
			if (!Injector::isInjected(pid)) {
				R3nzSkinInjector::cheatState = false;
				if (R3nzSkinInjector::btnState) {
					if (Injector::inject(pid))
						R3nzSkinInjector::cheatState = true;
					else
						R3nzSkinInjector::cheatState = false;
				}
				std::this_thread::sleep_for(1s);
			} else {
				R3nzSkinInjector::cheatState = true;
			}
		}
		std::this_thread::sleep_for(1s);
	}
}
