// AntiCheat.cpp
// C++17 required.

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <limits.h>
#include <unistd.h>
#endif

static constexpr int kIntegrityFailureExitCode = 3;
static constexpr char kTag[] = "[Javelin AntiCheat] ";

#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u
#endif

#pragma pack(push, 1)
struct IntegritySlot {
    char marker[24];
    std::uint32_t expected_crc32;
};
#pragma pack(pop)

#ifdef _MSC_VER
#pragma section(".jvlin", read)
__declspec(allocate(".jvlin"))
volatile const IntegritySlot kIntegritySlot = {
    {'J','A','V','E','L','I','N','_','C','R','C','3','2','_','S','L','O','T','_','V','1','\0','\0'},
    static_cast<std::uint32_t>(JAVELIN_EXPECTED_CRC32)
};
#else
__attribute__((used, section(".jvlin")))
volatile const IntegritySlot kIntegritySlot = {
    {'J','A','V','E','L','I','N','_','C','R','C','3','2','_','S','L','O','T','_','V','1','\0','\0'},
    static_cast<std::uint32_t>(JAVELIN_EXPECTED_CRC32)
};
#endif

static std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

static std::uint32_t crc32(const std::vector<std::uint8_t>& bytes) {
    std::uint32_t crc = 0xFFFFFFFFu;

    for (const std::uint8_t byte : bytes) {
        crc ^= byte;
        for (int bit = 0; bit != 8; ++bit) {
            const std::uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1u) ^ (0xEDB88320u & mask);
        }
    }

    return ~crc;
}

static bool readFile(const std::string& path, std::vector<std::uint8_t>& output) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }

    output.assign(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());

    return input.good() || input.eof();
}

static bool runningExecutablePath(std::string& path) {
#ifdef _WIN32
    std::vector<wchar_t> buffer(32768, L'\0');
    const DWORD count = GetModuleFileNameW(nullptr, buffer.data(),
                                            static_cast<DWORD>(buffer.size()));
    if (count == 0 || count >= buffer.size()) {
        return false;
    }

    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data(), static_cast<int>(count),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return false;
    }

    path.resize(static_cast<std::size_t>(required));
    return WideCharToMultiByte(
               CP_UTF8, WC_ERR_INVALID_CHARS, buffer.data(), static_cast<int>(count),
               path.data(), required, nullptr, nullptr) == required;
#else
    std::array<char, PATH_MAX + 1> buffer{};
    const ssize_t count = readlink("/proc/self/exe", buffer.data(), PATH_MAX);
    if (count <= 0 || count >= PATH_MAX) {
        return false;
    }

    path.assign(buffer.data(), static_cast<std::size_t>(count));
    return true;
#endif
}

static bool canonicalExecutableCrc(
    const std::vector<std::uint8_t>& executable,
    std::uint32_t& result) {
    const auto* marker = reinterpret_cast<const std::uint8_t*>(kIntegritySlot.marker);
    const std::size_t marker_size = sizeof(kIntegritySlot.marker);
    std::size_t slot_offset = executable.size();
    std::size_t matches = 0;

    for (std::size_t i = 0; i + sizeof(IntegritySlot) <= executable.size(); ++i) {
        if (std::equal(marker, marker + marker_size, executable.begin() + i)) {
            slot_offset = i;
            ++matches;
        }
    }

    if (matches != 1) {
        return false;
    }

    std::vector<std::uint8_t> canonical = executable;
    const std::size_t crc_offset = slot_offset + offsetof(IntegritySlot, expected_crc32);

    std::fill(
        canonical.begin() + static_cast<std::ptrdiff_t>(crc_offset),
        canonical.begin() + static_cast<std::ptrdiff_t>(crc_offset + sizeof(std::uint32_t)),
        0u);

    result = crc32(canonical);
    return true;
}

static bool verifyFileIntegrity(const std::string& path, std::uint32_t expected) {
    std::vector<std::uint8_t> bytes;
    std::uint32_t actual = 0;

    return readFile(path, bytes) &&
           canonicalExecutableCrc(bytes, actual) &&
           actual == expected;
}

static bool verifySelfIntegrity() {
    const std::uint32_t expected = kIntegritySlot.expected_crc32;

    // Zero explicitly means optional integrity checking is disabled.
    if (expected == 0u) {
        return true;
    }

    std::string executable_path;
    return runningExecutablePath(executable_path) &&
           verifyFileIntegrity(executable_path, expected);
}

#ifdef _WIN32
static bool debuggerDetected() {
    return IsDebuggerPresent() != FALSE;
}

static bool suspiciousProcessDetected() {
    static const std::array<const char*, 8> blocked = {{
        "cheatengine.exe", "ollydbg.exe", "x64dbg.exe", "httpdebuggerui.exe",
        "ida.exe", "ida64.exe", "scylla.exe", "processhacker.exe"
    }};

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W process{};
    process.dwSize = sizeof(process);

    bool found = false;
    if (Process32FirstW(snapshot, &process)) {
        do {
            char name[MAX_PATH]{};
            if (WideCharToMultiByte(CP_UTF8, 0, process.szExeFile, -1,
                                    name, MAX_PATH, nullptr, nullptr) > 0) {
                const std::string lowered = toLower(name);
                for (const char* candidate : blocked) {
                    if (lowered == candidate) {
                        found = true;
                        break;
                    }
                }
            }
        } while (!found && Process32NextW(snapshot, &process));
    }

    CloseHandle(snapshot);
    return found;
}
#else
static bool debuggerDetected() { return false; }
static bool suspiciousProcessDetected() { return false; }
#endif

int main(int argc, char* argv[]) {
    // Verification harness entry point: hashes a selected executable/file
    // using exactly the same canonicalization used for runtime verification.
    if (argc == 3 && std::string(argv[1]) == "--verify-file") {
        const std::uint32_t expected =
            static_cast<std::uint32_t>(std::strtoul(argv[2], nullptr, 16));
        return verifyFileIntegrity(argv[0], expected) ? 0 : kIntegrityFailureExitCode;
    }

    if (debuggerDetected()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return 1;
    }

    if (suspiciousProcessDetected()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return 2;
    }

    if (!verifySelfIntegrity()) {
        std::cerr << kTag << "Integrity check failed. Exiting.\n";
        return kIntegrityFailureExitCode;
    }

    std::cout << kTag << "All checks passed.\n";
    return 0;
}
