using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using TurbineAero.Core.Interfaces;

namespace TurbineAero.Services;

/// <summary>
/// Local file system storage service (fallback when FTP is not configured)
/// Note: This requires IWebHostEnvironment which should be injected in the Web project
/// </summary>
public class LocalFileStorageService : IFileStorageService
{
    private readonly string _baseDirectory;
    private readonly ILogger<LocalFileStorageService> _logger;

    public LocalFileStorageService(IConfiguration configuration, ILogger<LocalFileStorageService> logger)
    {
        var basePath = configuration["FileStorage:LocalBasePath"] ?? "uploads";
        // Use absolute path or relative to current directory
        _baseDirectory = Path.IsPathRooted(basePath) ? basePath : Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", basePath);
        _logger = logger;
        
        // Ensure base directory exists
        if (!Directory.Exists(_baseDirectory))
        {
            Directory.CreateDirectory(_baseDirectory);
        }
    }

    private string GetLocalPath(string remotePath)
    {
        var fullPath = Path.Combine(_baseDirectory, remotePath);
        var normalizedPath = Path.GetFullPath(fullPath);
        
        // Security: Ensure path is within base directory
        if (!normalizedPath.StartsWith(Path.GetFullPath(_baseDirectory), StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("Path traversal detected");
        }
        
        return normalizedPath;
    }

    public async Task<string> UploadFileAsync(Stream fileStream, string remotePath, CancellationToken cancellationToken = default)
    {
        try
        {
            var localPath = GetLocalPath(remotePath);
            var directory = Path.GetDirectoryName(localPath);
            
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            using var outputStream = new FileStream(localPath, FileMode.Create);
            await fileStream.CopyToAsync(outputStream, cancellationToken);

            _logger.LogInformation("File uploaded to local storage: {Path}", localPath);
            return localPath;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error uploading file to local storage: {RemotePath}", remotePath);
            throw;
        }
    }

    public async Task<Stream> DownloadFileAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        try
        {
            var localPath = GetLocalPath(remotePath);
            
            if (!File.Exists(localPath))
            {
                throw new FileNotFoundException($"File not found: {remotePath}");
            }

            var memoryStream = new MemoryStream();
            using var fileStream = new FileStream(localPath, FileMode.Open, FileAccess.Read);
            await fileStream.CopyToAsync(memoryStream, cancellationToken);
            memoryStream.Position = 0;

            return memoryStream;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error downloading file from local storage: {RemotePath}", remotePath);
            throw;
        }
    }

    public async Task DeleteFileAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        try
        {
            var localPath = GetLocalPath(remotePath);
            
            if (File.Exists(localPath))
            {
                File.Delete(localPath);
                _logger.LogInformation("File deleted from local storage: {Path}", localPath);
            }
            else
            {
                _logger.LogWarning("File not found for deletion: {Path}", localPath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting file from local storage: {RemotePath}", remotePath);
            throw;
        }
    }

    public Task<bool> FileExistsAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        var localPath = GetLocalPath(remotePath);
        return Task.FromResult(File.Exists(localPath));
    }
}
