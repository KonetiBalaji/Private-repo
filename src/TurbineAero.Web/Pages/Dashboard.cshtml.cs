using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using TurbineAero.Data;
using TurbineAero.Data.Models;

namespace TurbineAero.Web.Pages;

[Authorize]
public class DashboardModel : PageModel
{
    private readonly ApplicationDbContext _context;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<DashboardModel> _logger;

    public DashboardModel(
        ApplicationDbContext context,
        IWebHostEnvironment environment,
        ILogger<DashboardModel> logger)
    {
        _context = context;
        _environment = environment;
        _logger = logger;
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

        var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads", userId);
        if (!Directory.Exists(uploadsFolder))
        {
            Directory.CreateDirectory(uploadsFolder);
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
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                var userFile = new UserFile
                {
                    UserId = userId,
                    FileName = uniqueFileName,
                    OriginalFileName = file.FileName,
                    FilePath = filePath,
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

        if (file == null || !System.IO.File.Exists(file.FilePath))
        {
            return NotFound();
        }

        var fileBytes = await System.IO.File.ReadAllBytesAsync(file.FilePath);
        return File(fileBytes, file.ContentType, file.OriginalFileName);
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
            if (System.IO.File.Exists(file.FilePath))
            {
                System.IO.File.Delete(file.FilePath);
            }

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
}
