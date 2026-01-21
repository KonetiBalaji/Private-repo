using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Security.Claims;
using TurbineAero.Core.Interfaces;
using TurbineAero.Data;
using TurbineAero.Data.Models;

namespace TurbineAero.Web.Pages;

[Authorize]
public class DashboardModel : PageModel
{
    private readonly ApplicationDbContext _context;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<DashboardModel> _logger;
    private readonly IFileStorageService _fileStorageService;

    public DashboardModel(
        ApplicationDbContext context,
        IWebHostEnvironment environment,
        ILogger<DashboardModel> logger,
        IFileStorageService fileStorageService)
    {
        _context = context;
        _environment = environment;
        _logger = logger;
        _fileStorageService = fileStorageService;
    }

    public List<UserFile> Files { get; set; } = new();

    public async Task OnGetAsync()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.IsNullOrEmpty(userId))
        {
            try
            {
                Files = await _context.UserFiles
                    .Where(f => f.UserId == userId)
                    .OrderByDescending(f => f.UploadedAt)
                    .ToListAsync();
            }
            catch (Microsoft.Data.SqlClient.SqlException ex) when (ex.Number == 208) // Invalid object name
            {
                // Table doesn't exist yet - migration not applied
                _logger.LogWarning("UserFiles table does not exist. Please run: dotnet ef database update");
                Files = new List<UserFile>(); // Return empty list instead of crashing
            }
        }
    }

    public async Task<IActionResult> OnPostUploadAsync(List<IFormFile> files)
    {
        if (files == null || files.Count == 0)
        {
            return new JsonResult(new { success = false, message = "No files selected." })
            {
                StatusCode = 400
            };
        }

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return new JsonResult(new { success = false, message = "User not authenticated." })
            {
                StatusCode = 401
            };
        }

        var uploadedFiles = new List<object>();
        var errors = new List<string>();

        foreach (var file in files)
        {
            try
            {
                // Validate file type (only PDFs)
                if (!file.ContentType.Equals("application/pdf", StringComparison.OrdinalIgnoreCase) &&
                    !file.FileName.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase))
                {
                    errors.Add($"{file.FileName}: Only PDF files are allowed.");
                    continue;
                }

                // Validate file size (max 50MB)
                if (file.Length > 50 * 1024 * 1024)
                {
                    errors.Add($"{file.FileName}: File size exceeds 50MB limit.");
                    continue;
                }

                var uniqueFileName = $"{Guid.NewGuid()}_{file.FileName}";
                var remotePath = $"{userId}/{uniqueFileName}";

                // Upload to FTP
                using var fileStream = file.OpenReadStream();
                var ftpPath = await _fileStorageService.UploadFileAsync(fileStream, remotePath);

                var userFile = new UserFile
                {
                    UserId = userId,
                    FileName = uniqueFileName,
                    OriginalFileName = file.FileName,
                    FilePath = ftpPath, // Store FTP path instead of local path
                    FileSize = file.Length,
                    ContentType = file.ContentType,
                    UploadedAt = DateTime.UtcNow
                };

                _context.UserFiles.Add(userFile);
                await _context.SaveChangesAsync();

                uploadedFiles.Add(new
                {
                    id = userFile.Id,
                    fileName = userFile.OriginalFileName,
                    fileSize = userFile.FileSize,
                    uploadedAt = userFile.UploadedAt.ToString("yyyy-MM-dd HH:mm:ss")
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading file {FileName}", file.FileName);
                errors.Add($"{file.FileName}: {ex.Message}");
            }
        }

        if (uploadedFiles.Count > 0)
        {
            return new JsonResult(new
            {
                success = true,
                message = $"{uploadedFiles.Count} file(s) uploaded successfully.",
                files = uploadedFiles,
                errors = errors
            });
        }
        else
        {
            return new JsonResult(new
            {
                success = false,
                message = "No files were uploaded.",
                errors = errors
            })
            {
                StatusCode = 400
            };
        }
    }

    public async Task<IActionResult> OnGetDownloadAsync(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        var file = await _context.UserFiles
            .FirstOrDefaultAsync(f => f.Id == id && f.UserId == userId);

        if (file == null)
        {
            return NotFound();
        }

        try
        {
            // Extract remote path from FTP URL or use FilePath directly
            var remotePath = ExtractRemotePathFromFtpUrl(file.FilePath);
            var fileStream = await _fileStorageService.DownloadFileAsync(remotePath);
            
            return File(fileStream, file.ContentType, file.OriginalFileName);
        }
        catch (FileNotFoundException)
        {
            _logger.LogWarning("File not found on FTP: {FilePath}", file.FilePath);
            return NotFound();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error downloading file from FTP: {FilePath}", file.FilePath);
            return StatusCode(500, "Error downloading file.");
        }
    }

    public async Task<IActionResult> OnPostDeleteAsync([FromForm] int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return new JsonResult(new { success = false, message = "User not authenticated." })
            {
                StatusCode = 401
            };
        }

        var file = await _context.UserFiles
            .FirstOrDefaultAsync(f => f.Id == id && f.UserId == userId);

        if (file == null)
        {
            return new JsonResult(new { success = false, message = "File not found." })
            {
                StatusCode = 404
            };
        }

        try
        {
            // Extract remote path from FTP URL or use FilePath directly
            var remotePath = ExtractRemotePathFromFtpUrl(file.FilePath);
            await _fileStorageService.DeleteFileAsync(remotePath);

            _context.UserFiles.Remove(file);
            await _context.SaveChangesAsync();

            return new JsonResult(new { success = true, message = "File deleted successfully." });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting file {FileId}", id);
            return new JsonResult(new { success = false, message = $"Error deleting file: {ex.Message}" })
            {
                StatusCode = 500
            };
        }
    }

    /// <summary>
    /// Extracts the remote path from an FTP URL or returns the path as-is if it's already a relative path
    /// </summary>
    private string ExtractRemotePathFromFtpUrl(string filePath)
    {
        if (string.IsNullOrEmpty(filePath))
        {
            throw new ArgumentException("File path cannot be null or empty", nameof(filePath));
        }

        // If it's an FTP URL (starts with ftp:// or ftps://), extract the path
        if (filePath.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase) || 
            filePath.StartsWith("ftps://", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var uri = new Uri(filePath);
                var path = uri.PathAndQuery.TrimStart('/');
                
                // Remove the base path if it's included in the URL
                // For example: ftp://host/uploads/userId/file.pdf -> userId/file.pdf
                var pathParts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
                if (pathParts.Length > 1)
                {
                    // Skip the base path (usually "uploads") and return the rest
                    return string.Join("/", pathParts.Skip(1));
                }
                
                return path;
            }
            catch (UriFormatException ex)
            {
                _logger.LogWarning(ex, "Invalid FTP URL format: {FilePath}", filePath);
                // If URL parsing fails, try to extract path manually
                var parts = filePath.Split(new[] { "://" }, StringSplitOptions.None);
                if (parts.Length > 1)
                {
                    var afterProtocol = parts[1];
                    var slashIndex = afterProtocol.IndexOf('/');
                    if (slashIndex >= 0)
                    {
                        return afterProtocol.Substring(slashIndex + 1).TrimStart('/');
                    }
                }
                return filePath;
            }
        }
        
        // If it's already a relative path (e.g., "userId/filename.pdf"), return as-is
        return filePath;
    }
}
