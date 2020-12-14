#include <Windows.h>
#include "pch.h"


bool Hook(void* toHook, void* ourFunct, int len) {
	if (len < 5) {
		return false;
	}

	DWORD curProtection;
	VirtualProtect(toHook, len, PAGE_EXECUTE_READWRITE, &curProtection);

	memset(toHook, 0x90, len);

	DWORD relativeAddress = ((DWORD)ourFunct - (DWORD)toHook) - 5;

	*(BYTE*)toHook = 0xE9;
	*(DWORD*)((DWORD)toHook + 1) = relativeAddress;

	DWORD temp;
	VirtualProtect(toHook, len, curProtection, &temp);

	return true;
}

DWORD jmpBackAddy;
void __declspec(naked) ourFunct() {
	__asm {
		add ecx, ecx
		mov edx, [ebp - 8]
		jmp[jmpBackAddy]
	}
}

DWORD WINAPI MainThread(LPVOID param) {
	/* the assembly lines where we are going to hook is looks like this :
		2B 4D 08      subecx, [ebp + 08]
		8B 55 F8      movedx, [ebp - 08]
		89 0A         mov[edx], ecx
	*/
	int hookLength = 6;	//There are 3 bytes(< 5) in the first line, the hook funtion contains at least 1 `jmp` instrution(5 bytes) 
						// so that the offset length should be at least 5. But if we are using 5, we can only override the first line
						// and part of second line.
	DWORD hookAddress = 0x8d2768;	// signature if this address: 2B 4D 08 8B 55 F8
	jmpBackAddy = hookAddress + hookLength;

	Hook((void*)hookAddress, ourFunct, hookLength);

	while (true) {
		if (GetAsyncKeyState(VK_ESCAPE)) break;
		Sleep(50);
	}

	FreeLibraryAndExitThread((HMODULE)param, 0);

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, MainThread, hModule, 0, 0);
		break;
	}
	return TRUE;
}