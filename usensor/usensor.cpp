// usensor.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <windows.h>
#include <fltUser.h>
#include <iostream>
#include <fstream>
#include "events.h"
#include <ctime>
#include <string>
#include "psapi.h"

struct MESSAGE
{
	FILTER_MESSAGE_HEADER MessageHeader;
	EVENT Event;
};

int main()
{
	MESSAGE msg{};
	HANDLE   ConnectionPort = NULL;
	std::wofstream fout(L"events.log");
	HRESULT hr = FilterConnectCommunicationPort(COMM_PORT_NAME, 0, NULL, 0,
		NULL, &ConnectionPort);

	if (FAILED(hr)) {
		std::cout << "Failed to connect communication port " << std::hex << hr << std::endl;
		goto Exit;
	}

	while (1) {
		hr = FilterGetMessage(ConnectionPort, &msg.MessageHeader, sizeof(MESSAGE), NULL);
		if (FAILED(hr)) {
			std::cout << "Failed to get message " << std::hex << hr << std::endl;
			goto Exit;
		}

		std::wstring computerName;
		std::wstring userName;
		TCHAR  infoBuf[1024]{};
		DWORD  bufCharCount = 1024;

		// Get and display the name of the computer.
		if (!GetComputerName(infoBuf, &bufCharCount)) {
			computerName.assign(L"Unknown");
		}
		else {
			computerName.assign(infoBuf);
		}

		RtlZeroMemory(infoBuf, sizeof(infoBuf));
		// Get and display the user name.
		if (!GetUserName(infoBuf, &bufCharCount)) {
			userName.assign(L"Unknown");
		}
		else {
			userName.assign(infoBuf);
		}

		if ((msg.Event.eventType == kFileWrite) || (msg.Event.eventType == kProcessCreate)) {
			fout << computerName << L"," << userName << L",";

			std::time_t t = std::time(0);   // get time now
			std::tm* now = std::localtime(&t);
			fout << std::to_wstring(now->tm_hour) + L":" + std::to_wstring(now->tm_min) + L":" + std::to_wstring(now->tm_sec) + L","
				<< std::to_wstring(now->tm_mday) + L"-" + std::to_wstring(now->tm_mon + 1) + L"-" + std::to_wstring(now->tm_year + 1900) + L","
				;

			if (msg.Event.eventType == kFileWrite) {
				//std::wcout << msg.Event.fe.InitiatorName << " wrote file " << msg.Event.fe.Name << std::endl;

				fout << L"FileWrite," << msg.Event.fe.InitiatorName << L"," << msg.Event.fe.Name << std::endl;
			}
			else if (msg.Event.eventType == kProcessCreate) {
				HANDLE Handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, msg.Event.pe.Pid);
				if (Handle)
				{
					TCHAR Buffer[MAX_PATH];
					if (GetModuleFileNameEx(Handle, 0, Buffer, MAX_PATH))
					{
						memcpy(msg.Event.pe.Name, Buffer, sizeof(Buffer));
					}
					CloseHandle(Handle);
				}
				fout << L"ProcessCreate," << msg.Event.pe.InitiatorName << L"," << msg.Event.pe.Name << std::endl;
			}
		}
	}

Exit:
	if (ConnectionPort) {
		CloseHandle(ConnectionPort);
	}
	return 0;
}

