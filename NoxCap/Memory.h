#include <Windows.h>
namespace Memory
{
	template<typename T>
	T Read(DWORD address)
	{
		return *((T*)address);
	}

	template<typename T>
	void Write(DWORD address, T value)
	{
		*((T*)address) = value;
	}

	template<typename T>
	DWORD Protect(DWORD address, DWORD prot)
	{
		DWORD oldProt;
		VirtualProtect((LPVOID)address, sizeof(T), prot, &oldProt);
		return oldProt;
	}
	DWORD JumpHook(DWORD hookAt, DWORD newFunc, int size)
	{
		DWORD newOffset = newFunc - hookAt - 5; // -5 cuz its relative to the next instruction
		auto oldProtection = Memory::Protect<DWORD[3]>(hookAt + 1, PAGE_EXECUTE_READWRITE);
		Memory::Write<BYTE>(hookAt, 0xE9); //JMP
		Memory::Write<DWORD>(hookAt + 1, newOffset);
		for (unsigned int i = 5; i < size; i++) //NOP extra bytes so it doesnt corrupt any instructions
			Memory::Write<BYTE>(hookAt + i, 0x90);
		Memory::Protect<DWORD[3]>(hookAt + 1, oldProtection);
		return hookAt + 5;
	}
}