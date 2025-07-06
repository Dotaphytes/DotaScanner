// DotaScanner.cpp
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <openssl/evp.h>
#include <openssl/aes.h>

// Encryption/Decryption functions
extern "C" __declspec(dllexport) char* EncryptString(const char* input, const char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                      (const unsigned char*)key, 
                      (const unsigned char*)key);
    
    int len = strlen(input);
    int ciphertext_len = len + AES_BLOCK_SIZE;
    unsigned char* ciphertext = new unsigned char[ciphertext_len];
    
    int out_len;
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, 
                     (const unsigned char*)input, len);
    ciphertext_len = out_len;
    
    EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &out_len);
    ciphertext_len += out_len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Convert to base64
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_write(b64, ciphertext, ciphertext_len);
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    char* result = new char[bptr->length + 1];
    memcpy(result, bptr->data, bptr->length);
    result[bptr->length] = '\0';
    
    BIO_free_all(b64);
    delete[] ciphertext;
    
    return result;
}

extern "C" __declspec(dllexport) char* DecryptString(const char* input, const char* key) {
    // Decode base64 first
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input, -1);
    BIO_push(b64, mem);
    
    unsigned char* ciphertext = new unsigned char[strlen(input)];
    int ciphertext_len = BIO_read(b64, ciphertext, strlen(input));
    BIO_free_all(b64);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                      (const unsigned char*)key, 
                      (const unsigned char*)key);
    
    unsigned char* plaintext = new unsigned char[ciphertext_len];
    int plaintext_len;
    
    EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, 
                     ciphertext, ciphertext_len);
    int len = plaintext_len;
    
    EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &plaintext_len);
    len += plaintext_len;
    
    EVP_CIPHER_CTX_free(ctx);
    delete[] ciphertext;
    
    plaintext[len] = '\0';
    return (char*)plaintext;
}

// Memory scanning functions
struct MemoryRegion {
    uintptr_t base;
    size_t size;
};

std::vector<MemoryRegion> GetMemoryRegions(HANDLE process, HMODULE module) {
    std::vector<MemoryRegion> regions;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t base = (uintptr_t)module;
    uintptr_t max = base + 0x10000000; // Reasonable upper bound
    
    while (base < max && VirtualQueryEx(process, (LPCVOID)base, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            regions.push_back({(uintptr_t)mbi.BaseAddress, mbi.RegionSize});
        }
        base += mbi.RegionSize;
    }
    
    return regions;
}

extern "C" __declspec(dllexport) char* ScanForValue(const char* processName, float targetValue, int maxAddresses) {
    HANDLE hProcess = NULL;
    HMODULE hModule = NULL;
    
    // Find process
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (Process32First(snapshot, &entry)) {
        while (Process32Next(snapshot, &entry)) {
            if (_stricmp(entry.szExeFile, processName) == 0) {
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                break;
            }
        }
    }
    CloseHandle(snapshot);
    
    if (!hProcess) {
        return strdup("Process not found");
    }
    
    // Find module
    MODULEENTRY32 modEntry;
    modEntry.dwSize = sizeof(MODULEENTRY32);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, entry.th32ProcessID);
    
    if (Module32First(snapshot, &modEntry)) {
        while (Module32Next(snapshot, &modEntry)) {
            if (_stricmp(modEntry.szModule, "client.dll") == 0) {
                hModule = modEntry.hModule;
                break;
            }
        }
    }
    CloseHandle(snapshot);
    
    if (!hModule) {
        CloseHandle(hProcess);
        return strdup("Module not found");
    }
    
    // Scan memory
    std::vector<std::string> foundAddresses;
    auto regions = GetMemoryRegions(hProcess, hModule);
    uintptr_t moduleBase = (uintptr_t)hModule;
    
    for (const auto& region : regions) {
        if (foundAddresses.size() >= maxAddresses) break;
        
        uint8_t* buffer = new uint8_t[region.size];
        SIZE_T bytesRead;
        
        if (ReadProcessMemory(hProcess, (LPCVOID)region.base, buffer, region.size, &bytesRead)) {
            for (size_t i = 0; i < bytesRead - sizeof(float); i++) {
                float value = *reinterpret_cast<float*>(buffer + i);
                if (fabs(value - targetValue) < 0.001f) {
                    uintptr_t address = region.base + i;
                    uintptr_t offset = address - moduleBase;
                    
                    char addrStr[64];
                    sprintf_s(addrStr, "client.dll+%X", offset);
                    foundAddresses.push_back(addrStr);
                    
                    if (foundAddresses.size() >= maxAddresses) break;
                }
            }
        }
        
        delete[] buffer;
    }
    
    CloseHandle(hProcess);
    
    // Return as JSON array
    std::string result = "[";
    for (size_t i = 0; i < foundAddresses.size(); i++) {
        if (i > 0) result += ",";
        result += "\"" + foundAddresses[i] + "\"";
    }
    result += "]";
    
    return strdup(result.c_str());
}

extern "C" __declspec(dllexport) bool ModifyValue(const char* processName, const char* addressStr, float newValue) {
    // Parse address
    if (strncmp(addressStr, "client.dll+", 11) != 0) {
        return false;
    }
    
    uintptr_t offset;
    sscanf_s(addressStr + 11, "%X", &offset);
    
    // Find process and module (same as in ScanForValue)
    HANDLE hProcess = NULL;
    HMODULE hModule = NULL;
    
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (Process32First(snapshot, &entry)) {
        while (Process32Next(snapshot, &entry)) {
            if (_stricmp(entry.szExeFile, processName) == 0) {
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                break;
            }
        }
    }
    CloseHandle(snapshot);
    
    if (!hProcess) {
        return false;
    }
    
    MODULEENTRY32 modEntry;
    modEntry.dwSize = sizeof(MODULEENTRY32);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, entry.th32ProcessID);
    
    if (Module32First(snapshot, &modEntry)) {
        while (Module32Next(snapshot, &modEntry)) {
            if (_stricmp(modEntry.szModule, "client.dll") == 0) {
                hModule = modEntry.hModule;
                break;
            }
        }
    }
    CloseHandle(snapshot);
    
    if (!hModule) {
        CloseHandle(hProcess);
        return false;
    }
    
    // Calculate actual address
    uintptr_t actualAddress = (uintptr_t)hModule + offset;
    
    // Write new value
    SIZE_T bytesWritten;
    bool success = WriteProcessMemory(hProcess, (LPVOID)actualAddress, &newValue, sizeof(float), &bytesWritten);
    
    CloseHandle(hProcess);
    return success && (bytesWritten == sizeof(float));
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}