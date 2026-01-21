using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using TurbineAero.Core.Interfaces;

namespace TurbineAero.Services;

public class FtpFileStorageService : IFileStorageService
{
    private readonly string _ftpHost;
    private readonly string _ftpUsername;
    private readonly string _ftpPassword;
    private readonly string _ftpBasePath;
    private readonly bool _useSsl;
    private readonly ILogger<FtpFileStorageService> _logger;

    public FtpFileStorageService(IConfiguration configuration, ILogger<FtpFileStorageService> logger)
    {
        _ftpHost = configuration["Ftp:Host"] ?? throw new ArgumentNullException("Ftp:Host");
        _ftpUsername = configuration["Ftp:Username"] ?? throw new ArgumentNullException("Ftp:Username");
        _ftpPassword = configuration["Ftp:Password"] ?? throw new ArgumentNullException("Ftp:Password");
        _ftpBasePath = configuration["Ftp:BasePath"] ?? "/uploads";
        _useSsl = bool.TryParse(configuration["Ftp:UseSsl"], out var useSsl) && useSsl;
        _logger = logger;

        // Ignore SSL certificate errors for self-signed certificates (use with caution in production)
        if (_useSsl)
        {
            ServicePointManager.ServerCertificateValidationCallback = 
                (sender, certificate, chain, sslPolicyErrors) => true;
        }
    }

    private string GetFtpUrl(string remotePath)
    {
        var protocol = _useSsl ? "ftps" : "ftp";
        var basePath = _ftpBasePath.TrimStart('/').TrimEnd('/');
        var remotePathClean = remotePath.TrimStart('/');
        return $"{protocol}://{_ftpHost}/{basePath}/{remotePathClean}";
    }

    private FtpWebRequest CreateFtpRequest(string remotePath, string method)
    {
        var ftpUrl = GetFtpUrl(remotePath);
        var request = (FtpWebRequest)WebRequest.Create(ftpUrl);
        request.Credentials = new NetworkCredential(_ftpUsername, _ftpPassword);
        request.Method = method;
        request.UseBinary = true;
        request.UsePassive = true;
        request.EnableSsl = _useSsl;
        return request;
    }

    private async Task EnsureDirectoryExistsAsync(string directoryPath)
    {
        var parts = directoryPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var currentPath = "";

        foreach (var part in parts)
        {
            currentPath = string.IsNullOrEmpty(currentPath) ? part : $"{currentPath}/{part}";
            
            try
            {
                var request = CreateFtpRequest(currentPath, WebRequestMethods.Ftp.ListDirectory);
                using var response = (FtpWebResponse)await request.GetResponseAsync();
                response.Close();
            }
            catch (WebException ex) when (((FtpWebResponse)ex.Response)?.StatusCode == FtpStatusCode.ActionNotTakenFileUnavailable)
            {
                // Directory doesn't exist, create it
                var createRequest = CreateFtpRequest(currentPath, WebRequestMethods.Ftp.MakeDirectory);
                try
                {
                    using var createResponse = (FtpWebResponse)await createRequest.GetResponseAsync();
                    createResponse.Close();
                    _logger.LogInformation("Created FTP directory: {Directory}", currentPath);
                }
                catch (WebException createEx) when (((FtpWebResponse)createEx.Response)?.StatusCode == FtpStatusCode.ActionNotTakenFileUnavailable)
                {
                    // Directory might have been created by another request, ignore
                    _logger.LogWarning("Directory creation may have failed or already exists: {Directory}", currentPath);
                }
            }
        }
    }

    public async Task<string> UploadFileAsync(Stream fileStream, string remotePath, CancellationToken cancellationToken = default)
    {
        try
        {
            // Ensure the directory structure exists
            var directoryPath = Path.GetDirectoryName(remotePath)?.Replace('\\', '/') ?? "";
            if (!string.IsNullOrEmpty(directoryPath))
            {
                await EnsureDirectoryExistsAsync(directoryPath);
            }

            var request = CreateFtpRequest(remotePath, WebRequestMethods.Ftp.UploadFile);
            request.ContentLength = fileStream.Length;

            using (var requestStream = await request.GetRequestStreamAsync())
            {
                await fileStream.CopyToAsync(requestStream, cancellationToken);
            }

            using var response = (FtpWebResponse)await request.GetResponseAsync();
            var uploadedPath = GetFtpUrl(remotePath);
            _logger.LogInformation("File uploaded successfully to FTP: {Path}", uploadedPath);
            return uploadedPath;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error uploading file to FTP: {RemotePath}", remotePath);
            throw;
        }
    }

    public async Task<Stream> DownloadFileAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        try
        {
            var request = CreateFtpRequest(remotePath, WebRequestMethods.Ftp.DownloadFile);
            var response = (FtpWebResponse)await request.GetResponseAsync();
            var memoryStream = new MemoryStream();

            await response.GetResponseStream().CopyToAsync(memoryStream, cancellationToken);
            response.Close();
            memoryStream.Position = 0;

            return memoryStream;
        }
        catch (WebException ex) when (((FtpWebResponse)ex.Response)?.StatusCode == FtpStatusCode.ActionNotTakenFileUnavailable)
        {
            _logger.LogWarning("File not found on FTP: {RemotePath}", remotePath);
            throw new FileNotFoundException($"File not found: {remotePath}", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error downloading file from FTP: {RemotePath}", remotePath);
            throw;
        }
    }

    public async Task DeleteFileAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        try
        {
            var request = CreateFtpRequest(remotePath, WebRequestMethods.Ftp.DeleteFile);
            using var response = (FtpWebResponse)await request.GetResponseAsync();
            _logger.LogInformation("File deleted from FTP: {RemotePath}", remotePath);
        }
        catch (WebException ex) when (((FtpWebResponse)ex.Response)?.StatusCode == FtpStatusCode.ActionNotTakenFileUnavailable)
        {
            _logger.LogWarning("File not found for deletion on FTP: {RemotePath}", remotePath);
            // File doesn't exist, consider it already deleted
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting file from FTP: {RemotePath}", remotePath);
            throw;
        }
    }

    public async Task<bool> FileExistsAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        try
        {
            var request = CreateFtpRequest(remotePath, WebRequestMethods.Ftp.GetFileSize);
            using var response = (FtpWebResponse)await request.GetResponseAsync();
            return true;
        }
        catch (WebException ex) when (((FtpWebResponse)ex.Response)?.StatusCode == FtpStatusCode.ActionNotTakenFileUnavailable)
        {
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error checking file existence on FTP: {RemotePath}", remotePath);
            return false;
        }
    }
}
