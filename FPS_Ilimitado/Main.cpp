#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

std::string WideCharToString(const wchar_t* wideString) {
    int bufferSize = WideCharToMultiByte(CP_ACP, 0, wideString, -1, nullptr, 0, nullptr, nullptr);
    std::string convertedString(bufferSize, 0);
    WideCharToMultiByte(CP_ACP, 0, wideString, -1, &convertedString[0], bufferSize, nullptr, nullptr);
    return convertedString;
}

DWORD GetProcessID(const char* processName) {
    DWORD processID = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W procEntry;
        procEntry.dwSize = sizeof(procEntry);
        if (Process32FirstW(hSnap, &procEntry)) {
            do {
                std::string processNameConverted = WideCharToString(procEntry.szExeFile);
                if (_stricmp(processNameConverted.c_str(), processName) == 0) {
                    processID = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return processID;
}

uintptr_t GetModuleBaseAddress(DWORD processID, const char* moduleName) {
    uintptr_t moduleBaseAddress = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32FirstW(hSnap, &modEntry)) {
            do {
                std::string moduleNameConverted = WideCharToString(modEntry.szModule);
                if (_stricmp(moduleNameConverted.c_str(), moduleName) == 0) {
                    moduleBaseAddress = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return moduleBaseAddress;
}

bool SetFPS(DWORD processID, uintptr_t baseAddress, int newValue) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "[ERRO] Falha ao abrir o processo. Execute como Administrador." << std::endl;
        return false;
    }

    uintptr_t firstPointer = baseAddress + 0x00FB708C;
    DWORD addressLevel1, addressLevel2, addressLevel3;
    uintptr_t finalAddress = 0;

    if (!ReadProcessMemory(hProcess, (LPCVOID)firstPointer, &addressLevel1, sizeof(DWORD), NULL)) {
        CloseHandle(hProcess);
        return false;
    }

    if (!ReadProcessMemory(hProcess, (LPCVOID)(addressLevel1 + 0x8), &addressLevel2, sizeof(DWORD), NULL)) {
        CloseHandle(hProcess);
        return false;
    }

    if (!ReadProcessMemory(hProcess, (LPCVOID)(addressLevel2 + 0x0), &addressLevel3, sizeof(DWORD), NULL)) {
        CloseHandle(hProcess);
        return false;
    }

    finalAddress = addressLevel3 + 0x98;

    if (finalAddress < 0x10000 || finalAddress > 0x7FFFFFFF) {
        CloseHandle(hProcess);
        return false;
    }

    DWORD oldProtect;
    VirtualProtectEx(hProcess, (LPVOID)finalAddress, sizeof(int), PAGE_EXECUTE_READWRITE, &oldProtect);

    int fpsValue;
    ReadProcessMemory(hProcess, (LPCVOID)finalAddress, &fpsValue, sizeof(fpsValue), NULL);

    if (fpsValue != newValue) {
        WriteProcessMemory(hProcess, (LPVOID)finalAddress, &newValue, sizeof(newValue), NULL);
        std::cout << "[ALERT] FPS restaurado para " << newValue << std::endl;
    }

    VirtualProtectEx(hProcess, (LPVOID)finalAddress, sizeof(int), oldProtect, &oldProtect);
    CloseHandle(hProcess);
    return true;
}

int main() {
    const char* processName = "PointBlank.exe";
    DWORD processID = GetProcessID(processName);

    if (!processID) {
        std::cerr << "[ERRO] Processo não encontrado!" << std::endl;
        return 1;
    }

    uintptr_t baseAddress = GetModuleBaseAddress(processID, processName);
    if (!baseAddress) {
        std::cerr << "[ERRO] Endereço base não encontrado, por favor verifique as offsets." << std::endl;
        return 1;
    }

    std::cout << "[PROCESS] ID: " << processID << std::endl;
    std::cout << "[WARNING] Forçando a liberação de FPS..." << std::endl;

    while (true) {
        SetFPS(processID, baseAddress, 1000); //caso queira 500 de fps, só alterar o valor para 500
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
