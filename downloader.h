// downloader.h : Include file for standard system include files,
// or project specific include files.

#pragma once

enum class DownloadStatus {
    IDLE,
    DOWNLOADING,
    PAUSED,
    COMPLETED,
    FAILED,
    CANCELED
};

extern "C" {
    // Core download functionality
    __declspec(dllexport) void* startDownload(const char* url, const char* outputPath, int threadCount);
    __declspec(dllexport) long getFileSize(const char* url);
    
    __declspec(dllexport) bool pauseDownload(void* downloadContext);
    __declspec(dllexport) bool resumeDownload(void* downloadContext);
    __declspec(dllexport) bool cancelDownload(void* downloadContext);
    __declspec(dllexport) bool retryDownload(void* downloadContext);
    __declspec(dllexport) void cleanupDownload(void* downloadContext);

    // Status and progress monitoring
    __declspec(dllexport) DownloadStatus getDownloadStatus(void* downloadContext);
    __declspec(dllexport) float getDownloadProgress(void* downloadContext);
    __declspec(dllexport) float getDownloadSpeed(void* downloadContext);
    __declspec(dllexport) int getEstimatedTimeRemaining(void* downloadContext);
    __declspec(dllexport) const char* downloadStatusToString(DownloadStatus status);

    // Utility functions
    __declspec(dllexport) const char* calcSHA256(const char* filePath);
    __declspec(dllexport) const char* formatBytes(long bytes);
    __declspec(dllexport) const char* formatTime(int seconds);

	__declspec(dllexport) int shutdownDownloader();
}