#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Ws2_32.lib")


bool setAdminPrivileges()
{
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&NtAuthority, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdministratorsGroup))
	{
		if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
		{
			dwError = GetLastError();
		}
		FreeSid(pAdministratorsGroup);
	}

	if (!fIsRunAsAdmin)
	{
		char path[MAX_PATH];
		GetModuleFileNameA(NULL, path, MAX_PATH);
		ShellExecuteA(NULL, "runas", path, NULL, NULL, SW_SHOWNORMAL);
	}

	return fIsRunAsAdmin;
}

char* GetPublicIPv4() {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		return NULL;

	struct addrinfo* result = NULL, * ptr = NULL, hints;
	SOCKET ConnectSocket = INVALID_SOCKET;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (getaddrinfo("api.ipify.org", "http", &hints, &result) != 0) {
		WSACleanup();
		return NULL;
	}

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET)
			continue;

		if (connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		WSACleanup();
		return NULL;
	}

	const char* request = "GET / HTTP/1.1\r\nHost: api.ipify.org\r\n\r\n";
	if (send(ConnectSocket, request, (int)strlen(request), 0) == SOCKET_ERROR) {
		closesocket(ConnectSocket);
		WSACleanup();
		return NULL;
	}

	char recvbuf[512];
	if (recv(ConnectSocket, recvbuf, sizeof(recvbuf), 0) == SOCKET_ERROR) {
		closesocket(ConnectSocket);
		WSACleanup();
		return NULL;
	}

	closesocket(ConnectSocket);
	WSACleanup();

	char* ip_start = strstr(recvbuf, "\r\n\r\n");
	if (ip_start != NULL) {
		ip_start += 4;
		return _strdup(ip_start);
	}
	else {
		return NULL;
	}
}

const char* GetProcessorID()
{
	HRESULT hres;
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);

	hres = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	IWbemLocator* pLoc = NULL;
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc
	);

	IWbemServices* pSvc = NULL;
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pSvc
	);

	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT ProcessorId FROM Win32_Processor"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	char* processorID = NULL;

	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) {
			break;
		}

		VARIANT vtProp;
		hr = pclsObj->Get(L"ProcessorId", 0, &vtProp, 0, 0);
		if (SUCCEEDED(hr)) {
			processorID = _strdup(_com_util::ConvertBSTRToString(vtProp.bstrVal));
			VariantClear(&vtProp);
			break;
		}
		pclsObj->Release();
	}

	pSvc->Release();
	pLoc->Release();
	CoUninitialize();

	return processorID;
}

class TraceFiles
{
private:
	void randomize_string(char* str)
	{
		while (*str)
		{
			if (isalpha(*str))
				*str = (rand() % 2) ? 'A' + rand() % 26 : 'a' + rand() % 26;
			else if (isdigit(*str))
				*str = '0' + rand() % 10;
			str++;
		}
	}

	wchar_t* findRegistryValue(HKEY hKey, const wchar_t* searchString)
	{
		HKEY hSubKey;
		DWORD retCode;
		wchar_t achValue[16383];
		DWORD cchValue = 16383;
		DWORD dwType;
		BYTE bData[16383];
		DWORD dwDataSize = 16383;

		retCode = RegOpenKeyExW(hKey, NULL, 0, KEY_READ, &hSubKey);
		if (retCode != ERROR_SUCCESS)
			return NULL;

		for (DWORD index = 0;; index++)
		{
			cchValue = 16383;
			dwDataSize = 16383;
			retCode = RegEnumValueW(hSubKey, index, achValue, &cchValue, NULL, &dwType, bData, &dwDataSize);

			if (wcsstr(achValue, searchString) != NULL)
				return achValue;
			if (retCode == ERROR_NO_MORE_ITEMS)
				break;
		}

		RegCloseKey(hSubKey);
		return NULL;
	}
public:
	void MachineGuid()
	{
		HKEY hKey;
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WRITE, &hKey) == ERROR_SUCCESS)
		{
			char value[255];
			DWORD value_length = sizeof(value);
			if (RegQueryValueEx(hKey, findRegistryValue(hKey, L"MachineGuid"), NULL, NULL, (LPBYTE)&value, &value_length) == ERROR_SUCCESS)
			{
				randomize_string(value);
				if (RegSetValueEx(hKey, findRegistryValue(hKey, L"MachineGuid"), 0, REG_SZ, (LPBYTE)&value, value_length) == ERROR_SUCCESS)
					printf("[+] MachineGuid edited\n   %S\n", value);
				else
					printf("[-] Failed to edit MachineGuid\n");
			}
			else
				printf("[-] Failed to edit MachineGuid\n");
			RegCloseKey(hKey);
		}
		else
			printf("[-] Failed to edit MachineGuid\n");
	}

	void CloudStorageHash()
	{
		HKEY hKey;
		if (RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Smartly Dressed Games\\Unturned", 0, KEY_READ | KEY_WRITE, &hKey) == ERROR_SUCCESS)
		{
			if (RegDeleteValue(hKey, findRegistryValue(hKey, L"CloudStorage")) == ERROR_SUCCESS)
				printf("[+] Removed CloudStorageHash_h\n");
			else
				printf("[+] CloudStorageHash_h already removed\n");
			RegCloseKey(hKey);
		}
		else
			printf("[+] CloudStorageHash_h already removed\n");
	}

	void ConvenientSavedata()
	{
		char path[MAX_PATH];
		if (GetEnvironmentVariableA("ProgramFiles(x86)", path, MAX_PATH) > 0)
		{
			strcat_s(path, "\\Steam\\steamapps\\common\\Unturned\\Cloud\\ConvenientSavedata.json");
			if (DeleteFileA(path))
				printf("[+] Removed ConvenientSavedata.json\n");
			else
				printf("[+] ConvenientSavedata.json already removed\n");
		}
	}
};

int main()


{
	if (!setAdminPrivileges())
		return 0;
	SetConsoleTitle(L"cv3os https://github.com/mhhjkx");
	TraceFiles().CloudStorageHash();
	TraceFiles().ConvenientSavedata();
	TraceFiles().MachineGuid();

	if (auto ip = GetPublicIPv4())
		printf("[+] Public IPv4:\n   %s\n", ip);
	else
		printf("[-] Failed to get Public IPv4\n");

	if (auto processorID = GetProcessorID())
		printf("[+] Processor ID:\n   %s\n", processorID);
	else
		printf("[-] Failed to get Processor ID.\n");
	printf("\n");
	system("pause");
	return 0;
}
