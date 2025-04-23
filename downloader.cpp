#include "downloader.h"
#include <windows.h>
#include <winhttp.h>
#include <thread>
#include <vector>
#include <fstream>
#include <string>
#include <memory>
#include <mutex>
#include <iostream>
#include <atomic>
#include <chrono>
#include <map>
#include <condition_variable>
#include <openssl/sha.h>
#include <openssl/evp.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")


int downloadRange(const char* url, const char* output, long start, long end,
    std::atomic<bool>& cancelFlag, std::atomic<bool>& pauseFlag,
    std::condition_variable& pauseCV, std::mutex& pauseMutex);
int downloadFile(const char* url, const char* outputPath,
    std::atomic<bool>& cancelFlag, std::atomic<bool>& pauseFlag,
    std::condition_variable& pauseCV, std::mutex& pauseMutex);
int multiDownload(const char* url, const char* outputPath, int threadCount, long fileSize,
    std::atomic<bool>& cancelFlag, std::atomic<bool>& pauseFlag,
    std::condition_variable& pauseCV, std::mutex& pauseMutex);
const char* calcSHA256(const char* filePath);
long getFileSize(const char* url);
float getDownloadSpeed(void* downloadContext);


// Download context structure
struct DownloadContext {
    std::string url;
    std::string outputPath;
    int threadCount;
    long fileSize;
    std::atomic<DownloadStatus> status{ DownloadStatus::IDLE };
    std::atomic<bool> cancelFlag{ false };
    std::atomic<bool> pauseFlag{ false };
    std::condition_variable pauseCV;
    std::mutex pauseMutex;
    std::thread downloadThread;
    std::atomic<int> retryCount{ 0 };
    std::atomic<int> maxRetries{ 3 };
    std::atomic<long> bytesDownloaded{ 0 };
    std::chrono::steady_clock::time_point startTime;

    DownloadContext(const char* _url, const char* _output, int _threadCount = 4)
        : url(_url), outputPath(_output), threadCount(_threadCount), fileSize(-1) {
    }
};

// Global mutex to protect I/O operations
std::mutex io_mutex;

// Global map to store download contexts
std::map<std::string, std::shared_ptr<DownloadContext>> activeDownloads;
std::mutex activeDownloadsMutex;

constexpr long SIZE_THRESHOLD = 50 * 1024 * 1024;
unsigned int numThreads = std::thread::hardware_concurrency();

// Parse URL into components
bool parseURL(const char* url, std::wstring& hostName, std::wstring& urlPath, INTERNET_PORT& port, bool& isHttps) {
    URL_COMPONENTS urlComp;
    WCHAR szHostName[256];
    WCHAR szUrlPath[2048];
    WCHAR szScheme[32];

    // Initialize the URL_COMPONENTS structure
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);

    // Set required component lengths to non-zero 
    urlComp.dwSchemeLength = sizeof(szScheme) / sizeof(szScheme[0]);
    urlComp.dwHostNameLength = sizeof(szHostName) / sizeof(szHostName[0]);
    urlComp.dwUrlPathLength = sizeof(szUrlPath) / sizeof(szUrlPath[0]);

    // Set required components pointers
    urlComp.lpszScheme = szScheme;
    urlComp.lpszHostName = szHostName;
    urlComp.lpszUrlPath = szUrlPath;

    // Convert URL to wide characters
    int urlLength = MultiByteToWideChar(CP_UTF8, 0, url, -1, NULL, 0);
    if (urlLength == 0) return false;

    std::wstring wideUrl(urlLength, 0);
    MultiByteToWideChar(CP_UTF8, 0, url, -1, &wideUrl[0], urlLength);

    // Crack the URL
    if (!WinHttpCrackUrl(wideUrl.c_str(), static_cast<DWORD>(wideUrl.length()), 0, &urlComp)) {
        std::cerr << "Failed to parse URL: " << url << std::endl;
        return false;
    }

    szScheme[sizeof(szScheme) / sizeof(szScheme[0]) - 1] = L'\0';
    isHttps = (wcscmp(urlComp.lpszScheme, L"https") == 0);

    hostName = std::wstring(urlComp.lpszHostName, urlComp.dwHostNameLength);
    urlPath = std::wstring(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    port = urlComp.nPort;

    return true;
}

long getFileSize(const char* url) {
    long fileSize = -1;

    std::wstring hostName, urlPath;
    INTERNET_PORT port;
    bool isHttps;

    if (!parseURL(url, hostName, urlPath, port, isHttps)) {
        return -1;
    }

    // Initialize WinHTTP
    HINTERNET hSession = WinHttpOpen(L"WinHTTP Downloader/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession) {
        std::cerr << "Failed to initialize WinHTTP session" << std::endl;
        return -1;
    }

    // Connect to server
    HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        std::cerr << "Failed to connect to server" << std::endl;
        return -1;
    }

    // Create request handle
    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"HEAD",
        urlPath.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        std::cerr << "Failed to create request handle" << std::endl;
        return -1;
    }

    // Send request
    if (!WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        std::cerr << "Failed to send request" << std::endl;
        return -1;
    }

    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        std::cerr << "Failed to receive response" << std::endl;
        return -1;
    }

    // Check for content length header
    DWORD headerSize = 0;

    // First call to get header size
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_CONTENT_LENGTH,
        WINHTTP_HEADER_NAME_BY_INDEX,
        NULL,
        &headerSize,
        WINHTTP_NO_HEADER_INDEX);

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<wchar_t> buffer(headerSize / sizeof(wchar_t));

        // Second call to get actual header
        if (WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_CONTENT_LENGTH,
            WINHTTP_HEADER_NAME_BY_INDEX,
            buffer.data(),
            &headerSize,
            WINHTTP_NO_HEADER_INDEX)) {
            fileSize = wcstol(buffer.data(), NULL, 10);
        }
    }

    // Clean up
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return fileSize;
}

// Helper function to read progress file
long readProgressFile(const std::string& progressFilePath) {
    std::ifstream progress(progressFilePath);
    if (!progress.is_open()) {
        return 0;
    }

    long downloadedBytes = 0;
    progress >> downloadedBytes;
    progress.close();
    return downloadedBytes;
}

int multiDownload(const char* url, const char* outputPath, int threadCount, long fileSize,
    std::atomic<bool>& cancelFlag, std::atomic<bool>& pauseFlag,
    std::condition_variable& pauseCV, std::mutex& pauseMutex) {
    if (!url || !outputPath || threadCount <= 0) {
        std::cerr << "Args is invalid" << std::endl;
        return -1;
    }

    if (fileSize < 0) {
        fileSize = getFileSize(url);
        if (fileSize < 0) {
            std::cerr << "Failed to determine file size" << std::endl;
            return -1;
        }
    }

    if (threadCount > numThreads) {
        std::cerr << "Thread count exceeds the maximum number of threads supported by the system." << std::endl;
        threadCount = numThreads;
    }

    if (threadCount > 12) {
        std::cerr << "Thread count exceeds the maximum limit of 12. More thread not same more faster" << std::endl;
        threadCount = 12;
    }

    if (threadCount == 1 || fileSize < SIZE_THRESHOLD) {
        std::cout << "Using direct download (threadCount=" << threadCount
            << ", fileSize=" << fileSize << " bytes)" << std::endl;
        return downloadFile(url, outputPath, cancelFlag, pauseFlag, pauseCV, pauseMutex);
    }

    long chunkSize = fileSize / threadCount;

    // Check for existing progress files
    std::vector<long> progressValues(threadCount, 0);
    bool hasProgress = false;

    for (int i = 0; i < threadCount; i++) {
        std::string progressFilePath = std::string(outputPath) + ".part" + std::to_string(i) + ".progress";
        progressValues[i] = readProgressFile(progressFilePath);
        if (progressValues[i] > 0) {
            hasProgress = true;
        }
    }

    if (hasProgress) {
        std::cout << "Resuming previous download..." << std::endl;
    }

    // Initialize threads
    std::vector<std::thread> threads;
    std::vector<int> results(threadCount, 0);

    for (int i = 0; i < threadCount; i++) {
        long start = i * chunkSize;
        long end = (i == threadCount - 1) ? fileSize - 1 : (start + chunkSize - 1);

        // Adjust start position for resuming
        start += progressValues[i];

        std::string partFile = std::string(outputPath) + ".part" + std::to_string(i);

        if (start > end) {
            // This part is already fully downloaded
            results[i] = 0;
            continue;
        }

        threads.emplace_back([url, partFile, start, end, &results, i, &cancelFlag, &pauseFlag, &pauseCV, &pauseMutex]() {
            results[i] = downloadRange(url, partFile.c_str(), start, end, cancelFlag, pauseFlag, pauseCV, pauseMutex);
            });
    }

    // Wait for all threads to complete
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    // Check if download was cancelled
    if (cancelFlag) {
        std::cout << "Download cancelled" << std::endl;
        return -2;  // Special return code for cancellation
    }

    // Check results
    for (int i = 0; i < threadCount; i++) {
        if (results[i] != 0) {
            std::cerr << "Error when downloading part " << i << std::endl;
            return -1;
        }
    }

    // Merge files
    try {
        std::ofstream out(outputPath, std::ios::binary);
        if (!out.is_open()) {
            std::cerr << "Cannot open output file: " << outputPath << std::endl;
            return -1;
        }

        for (int i = 0; i < threadCount; i++) {
            std::string partFile = std::string(outputPath) + ".part" + std::to_string(i);
            std::ifstream in(partFile, std::ios::binary);

            if (!in.is_open()) {
                std::cerr << "Cannot open part: " << partFile << std::endl;
                out.close();
                return -1;
            }

            out << in.rdbuf();
            in.close();
            
            DeleteFileA(partFile.c_str());
            DeleteFileA((partFile + ".progress").c_str());
        }

        out.close();
    }
    catch (const std::exception& e) {
        std::cerr << "Error when merging file: " << e.what() << std::endl;
        return -1;
    }

	if (fileSize > 0) {
		std::ifstream in(outputPath, std::ios::binary | std::ios::ate);
		if (in.is_open()) {
			long actualSize = in.tellg();
			in.close();
			if (actualSize != fileSize) {
				std::cerr << "Downloaded file size does not match expected size." << std::endl;
				return -1;
			}
		}
	}
    return 0;
}

int downloadFile(const char* url, const char* outputPath,
    std::atomic<bool>& cancelFlag, std::atomic<bool>& pauseFlag,
    std::condition_variable& pauseCV, std::mutex& pauseMutex) {
    return downloadRange(url, outputPath, 0, -1, cancelFlag, pauseFlag, pauseCV, pauseMutex);
}

int downloadRange(const char* url, const char* output, long start, long end,
    std::atomic<bool>& cancelFlag, std::atomic<bool>& pauseFlag,
    std::condition_variable& pauseCV, std::mutex& pauseMutex) {
    if (!url || !output || start < 0 || (end < start && end != -1)) {
        return -1;
    }

    if (cancelFlag) {
        return -2;  // Special return code for cancellation
    }

    std::wstring hostName, urlPath;
    INTERNET_PORT port;
    bool isHttps;

    if (!parseURL(url, hostName, urlPath, port, isHttps)) {
        return -1;
    }

    // Check for existing progress
    long currentProgress = 0;
    std::string progressFilePath = std::string(output) + ".progress";
    currentProgress = readProgressFile(progressFilePath);

    if (currentProgress > 0 && end != -1) {
        // Adjust start position for resuming
        start += currentProgress;
        if (start > end) {
            // This part is already fully downloaded
            return 0;
        }
    }

    // Initialize WinHTTP
    HINTERNET hSession = WinHttpOpen(L"WinHTTP Downloader/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession) {
        std::cerr << "Failed to initialize WinHTTP session" << std::endl;
        return -1;
    }

    // Connect to server
    HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        std::cerr << "Failed to connect to server" << std::endl;
        return -1;
    }

    // Create request handle
    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    flags |= WINHTTP_FLAG_REFRESH;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"GET",
        urlPath.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        std::cerr << "Failed to create request handle" << std::endl;
        return -1;
    }

    // Set range header if needed
    if (end != -1) {
        wchar_t rangeHeader[128];
        swprintf_s(rangeHeader, sizeof(rangeHeader) / sizeof(wchar_t), L"Range: bytes=%ld-%ld", start, end);

        if (!WinHttpAddRequestHeaders(hRequest,
            rangeHeader,
            -1,
            WINHTTP_ADDREQ_FLAG_ADD)) {
            std::cerr << "Failed to add range header" << std::endl;
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return -1;
        }
    }
    else if (currentProgress > 0) {
        // For full file download with resuming
        wchar_t rangeHeader[128];
        swprintf_s(rangeHeader, sizeof(rangeHeader) / sizeof(wchar_t), L"Range: bytes=%ld-", currentProgress);

        if (!WinHttpAddRequestHeaders(hRequest,
            rangeHeader,
            -1,
            WINHTTP_ADDREQ_FLAG_ADD)) {
            std::cerr << "Failed to add range header for resuming" << std::endl;
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return -1;
        }
    }

    // Send request
    if (!WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        std::cerr << "Failed to send request" << std::endl;
        return -1;
    }

    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        std::cerr << "Failed to receive response" << std::endl;
        return -1;
    }

    // Check status code
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL,
        &statusCode,
        &statusSize,
        NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        std::cerr << "Failed to query status code" << std::endl;
        return -1;
    }

    // For range requests, status should be 206 (Partial Content)
    // For full file, status should be 200 (OK)
    bool isResumingOrRange = (currentProgress > 0 || end != -1);

    if (isResumingOrRange && statusCode != 206) {
        if (statusCode == 200) {
            // Server doesn't support range requests, try to download the whole file
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return downloadRange(url, output, 0, -1, cancelFlag, pauseFlag, pauseCV, pauseMutex);
        }
        else {
            std::cerr << "Server returned error status: " << statusCode << std::endl;
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return -1;
        }
    }
    else if (!isResumingOrRange && statusCode != 200) {
        std::cerr << "Server returned error status: " << statusCode << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }

    // Open output file
    std::ios_base::openmode mode = std::ios::binary;
    if (currentProgress > 0) {
        mode |= std::ios::app;  // Append if resuming
    }
    std::ofstream out(output, mode);
    if (!out.is_open()) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        std::cerr << "Failed to open output file: " << output << std::endl;
        return -1;
    }

    // Open progress file
    std::ofstream progressFile(progressFilePath, std::ios::trunc);

    // Read data
    constexpr DWORD BUFFER_SIZE = 8192;
    std::unique_ptr<char[]> buffer(new char[BUFFER_SIZE]);
    DWORD bytesRead = 0;
    DWORD bytesAvailable = 0;
    long totalBytesProcessed = currentProgress;

    do {
        // Check for cancellation
        if (cancelFlag) {
            out.close();
            if (progressFile.is_open()) progressFile.close();
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return -2;  // Special return code for cancellation
        }

        // Check for pause
        if (pauseFlag) {
            {
                std::unique_lock<std::mutex> lock(pauseMutex);
                if (pauseFlag) {  // Double-check after acquiring lock
                    pauseCV.wait(lock, [&pauseFlag] { return !pauseFlag; });
                }
            }
        }

        // Check for available data
        bytesAvailable = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) {
            std::cerr << "Error in WinHttpQueryDataAvailable: " << GetLastError() << std::endl;
            out.close();
            if (progressFile.is_open()) progressFile.close();
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return -1;
        }

        if (bytesAvailable == 0) {
            break;
        }

        // Read data (up to buffer size)
        DWORD bytesToRead = (bytesAvailable > BUFFER_SIZE) ? BUFFER_SIZE : bytesAvailable;

        if (!WinHttpReadData(hRequest, buffer.get(), bytesToRead, &bytesRead)) {
            std::cerr << "Error in WinHttpReadData: " << GetLastError() << std::endl;
            out.close();
            if (progressFile.is_open()) progressFile.close();
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return -1;
        }

        // Write data to file
        if (bytesRead > 0) {
            out.write(buffer.get(), bytesRead);
            totalBytesProcessed += bytesRead;

            // Update progress file
            if (progressFile.is_open()) {
                progressFile.seekp(0);
                progressFile << totalBytesProcessed;
                progressFile.flush();
            }

            // Update bytes downloaded for progress monitoring
            {
                std::lock_guard<std::mutex> lock(io_mutex);
                // Find download context and update bytes downloaded
                for (auto& pair : activeDownloads) {
                    if (std::string(output).find(pair.second->outputPath) != std::string::npos) {
                        pair.second->bytesDownloaded += bytesRead;
                        break;
                    }
                }
            }
        }
    } while (bytesRead > 0);

    // Close files and handles
    out.close();
    if (progressFile.is_open()) progressFile.close();

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return 0;
}

const char* calcSHA256(const char* filePath) {
    thread_local char hashString[65];

    if (!filePath) {
        return nullptr;
    }

    FILE* file = nullptr;
    if (fopen_s(&file, filePath, "rb") != 0) {
        return nullptr;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(file);
        return nullptr;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return nullptr;
    }

    constexpr size_t BUFFER_SIZE = 8192;
    std::unique_ptr<char[]> buffer(new char[BUFFER_SIZE]);
    size_t bytesRead = 0;

    while ((bytesRead = fread(buffer.get(), 1, BUFFER_SIZE, file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer.get(), bytesRead) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return nullptr;
        }
    }

    fclose(file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (EVP_DigestFinal_ex(ctx, hash, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return nullptr;
    }

    EVP_MD_CTX_free(ctx);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf_s(&hashString[i * 2], 3, "%02x", hash[i]);
    }
    hashString[64] = 0;

    return hashString;
}

void* startDownload(const char* url, const char* outputPath, int threadCount = 4) {
    if (!url || !outputPath) {
        std::cerr << "Invalid parameters for download" << std::endl;
        return nullptr;
    }

    std::string downloadId = std::string(url) + "_" + std::string(outputPath);

    {
        std::lock_guard<std::mutex> lock(activeDownloadsMutex);

        // Check if download already exists
        if (activeDownloads.find(downloadId) != activeDownloads.end()) {
            auto status = activeDownloads[downloadId]->status.load();
            if (status == DownloadStatus::DOWNLOADING || status == DownloadStatus::PAUSED) {
                std::cerr << "Download already in progress" << std::endl;
                return activeDownloads[downloadId].get();
            }
        }

        // Create new download context
        auto context = std::make_shared<DownloadContext>(url, outputPath, threadCount);
        activeDownloads[downloadId] = context;

        // Get file size
        context->fileSize = getFileSize(url);
        if (context->fileSize < 0) {
            std::cerr << "Failed to determine file size" << std::endl;
            context->status = DownloadStatus::FAILED;
            return context.get();
        }

        // Start download in a separate thread
        context->status = DownloadStatus::DOWNLOADING;
        context->startTime = std::chrono::steady_clock::now();

        context->downloadThread = std::thread([context]() {
            int result = multiDownload(
                context->url.c_str(),
                context->outputPath.c_str(),
                context->threadCount,
                context->fileSize,
                context->cancelFlag,
                context->pauseFlag,
                context->pauseCV,
                context->pauseMutex
            );

            if (result == 0) {
                context->status = DownloadStatus::COMPLETED;
            }
            else if (result == -2) {
                context->status = DownloadStatus::CANCELED;
            }
            else {
                // Check if we should retry
                if (context->retryCount < context->maxRetries && !context->cancelFlag) {
                    context->retryCount++;
                    std::cout << "Retry attempt " << context->retryCount << " of " << context->maxRetries << std::endl;

                    // Wait a bit before retrying
                    std::this_thread::sleep_for(std::chrono::seconds(2));

                    // Try again
                    result = multiDownload(
                        context->url.c_str(),
                        context->outputPath.c_str(),
                        context->threadCount,
                        context->fileSize,
                        context->cancelFlag,
                        context->pauseFlag,
                        context->pauseCV,
                        context->pauseMutex
                    );

                    if (result == 0) {
                        context->status = DownloadStatus::COMPLETED;
                    }
                    else if (result == -2) {
                        context->status = DownloadStatus::CANCELED;
                    }
                    else {
                        context->status = DownloadStatus::FAILED;
                    }
                }
                else {
                    context->status = DownloadStatus::FAILED;
                }
            }
            });

        return context.get();
    }
}

bool pauseDownload(void* downloadContext) {
    auto* context = static_cast<DownloadContext*>(downloadContext);
    if (!context || context->status != DownloadStatus::DOWNLOADING) {
        return false;
    }

    context->pauseFlag = true;
    context->status = DownloadStatus::PAUSED;
    std::cout << "Download paused" << std::endl;
    return true;
}

bool resumeDownload(void* downloadContext) {
    auto* context = static_cast<DownloadContext*>(downloadContext);
    if (!context || context->status != DownloadStatus::PAUSED) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(context->pauseMutex);
        context->pauseFlag = false;
        context->status = DownloadStatus::DOWNLOADING;
    }
    context->pauseCV.notify_all();
    std::cout << "Download resumed" << std::endl;
    return true;
}

bool cancelDownload(void* downloadContext) {
    auto* context = static_cast<DownloadContext*>(downloadContext);
    if (!context || (context->status != DownloadStatus::DOWNLOADING &&
        context->status != DownloadStatus::PAUSED)) {
        return false;
    }

    // Set cancel flag
    context->cancelFlag = true;

    // If download is paused, need to resume it first so it can detect the cancellation
    if (context->status == DownloadStatus::PAUSED) {
        std::lock_guard<std::mutex> lock(context->pauseMutex);
        context->pauseFlag = false;
        context->pauseCV.notify_all();
    }

    std::cout << "Download cancelled" << std::endl;
    return true;
}

bool retryDownload(void* downloadContext) {
    auto* context = static_cast<DownloadContext*>(downloadContext);
    if (!context || context->status != DownloadStatus::FAILED) {
        return false;
    }

    // Wait for previous thread to finish if it's still running
    if (context->downloadThread.joinable()) {
        context->downloadThread.join();
    }

    // Reset flags and counters
    context->cancelFlag = false;
    context->pauseFlag = false;
    context->bytesDownloaded = 0;
    context->status = DownloadStatus::DOWNLOADING;
    context->startTime = std::chrono::steady_clock::now();

    // Start download in a new thread
    context->downloadThread = std::thread([context]() {
        int result = multiDownload(
            context->url.c_str(),
            context->outputPath.c_str(),
            context->threadCount,
            context->fileSize,
            context->cancelFlag,
            context->pauseFlag,
            context->pauseCV,
            context->pauseMutex
        );

        if (result == 0) {
            context->status = DownloadStatus::COMPLETED;
        }
        else if (result == -2) {
            context->status = DownloadStatus::CANCELED;
        }
        else {
            context->status = DownloadStatus::FAILED;
        }
        });

    std::cout << "Download retry started" << std::endl;
    return true;
}

DownloadStatus getDownloadStatus(void* downloadContext) {
    auto* context = static_cast<DownloadContext*>(downloadContext);
    if (!context) {
        return DownloadStatus::IDLE;
    }

    return context->status;
}

float getDownloadProgress(void* downloadContext) {
    auto* context = static_cast<DownloadContext*>(downloadContext);
    if (!context || context->fileSize <= 0) {
        return 0.0f;
    }

    return static_cast<float>(context->bytesDownloaded) / context->fileSize;
}

float getDownloadSpeed(void* downloadContext) {
    auto* context = static_cast<DownloadContext*>(downloadContext);
    if (!context || context->bytesDownloaded <= 0) {
        return 0.0f;
    }

    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - context->startTime).count();

    if (duration <= 0) {
        return 0.0f;
    }

    // Return speed in KB/s
    return (context->bytesDownloaded / 1024.0f) / (duration / 1000.0f);
}

int getEstimatedTimeRemaining(void* downloadContext) {
    auto* context = static_cast<DownloadContext*>(downloadContext);
    if (!context || context->fileSize <= 0 || context->bytesDownloaded <= 0) {
        return -1;
    }

    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - context->startTime).count();

    if (duration <= 0) {
        return -1;
    }

    float bytesPerSecond = context->bytesDownloaded / static_cast<float>(duration);
    if (bytesPerSecond <= 0) {
        return -1;
    }

    long bytesRemaining = context->fileSize - context->bytesDownloaded;
    return static_cast<int>(bytesRemaining / bytesPerSecond);
}

void cleanupDownload(void* downloadContext) {
    auto* context = static_cast<DownloadContext*>(downloadContext);
    if (!context) {
        return;
    }

    std::string downloadId = context->url + "_" + context->outputPath;

    {
        std::lock_guard<std::mutex> lock(activeDownloadsMutex);

        // Wait for thread to finish if needed
        if (context->downloadThread.joinable()) {
            // If it's still running, cancel it
            if (context->status == DownloadStatus::DOWNLOADING ||
                context->status == DownloadStatus::PAUSED) {
                context->cancelFlag = true;

                if (context->status == DownloadStatus::PAUSED) {
                    std::lock_guard<std::mutex> pauseLock(context->pauseMutex);
                    context->pauseFlag = false;
                    context->pauseCV.notify_all();
                }
            }

            context->downloadThread.join();
        }

        // Remove from active downloads
        activeDownloads.erase(downloadId);
    }
}

const char* downloadStatusToString(DownloadStatus status) {
    switch (status) {
    case DownloadStatus::IDLE:
        return "Idle";
    case DownloadStatus::DOWNLOADING:
        return "Downloading";
    case DownloadStatus::PAUSED:
        return "Paused";
    case DownloadStatus::COMPLETED:
        return "Completed";
    case DownloadStatus::FAILED:
        return "Failed";
    case DownloadStatus::CANCELED:
        return "Canceled";
    default:
        return "Unknown";
    }
}


const char* formatBytes(long bytes) {  
   const char* units[] = { "B", "KB", "MB", "GB", "TB" };  
   int unitIndex = 0;  
   double size = bytes;  

   while (size >= 1024 && unitIndex < 4) {  
       size /= 1024;  
       unitIndex++;  
   }  

   static thread_local char buffer[32]; 
   if (unitIndex == 0) {  
       sprintf_s(buffer, sizeof(buffer), "%ld %s", static_cast<long>(size), units[unitIndex]);  
   } else {  
       sprintf_s(buffer, sizeof(buffer), "%.2f %s", size, units[unitIndex]);  
   }  

   return buffer;  
}

const char* formatTime(int seconds) {
    if (seconds < 0) {
        return "Unknown";
    }
	if (seconds == 0) {
		return "0s";
	}

    int hours = seconds / 3600;
    int minutes = (seconds % 3600) / 60;
    seconds = seconds % 60;
    
    static thread_local char buffer[32];
    if (hours > 0) {
        sprintf_s(buffer, sizeof(buffer), "%d:%02d:%02d", hours, minutes, seconds);
    }
    else {
        sprintf_s(buffer, sizeof(buffer), "%d:%02d", minutes, seconds);
    }

    return buffer;
}

int shutdownDownloader() {
	std::cout << "Shutting down downloader..." << std::endl;
	for (auto& pair : activeDownloads) {
		cleanupDownload(pair.second.get());
	}
	activeDownloads.clear();
	WinHttpCloseHandle(NULL);
	std::cout << "Downloader shut down successfully." << std::endl;
	return 0;
}