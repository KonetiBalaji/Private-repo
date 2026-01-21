namespace TurbineAero.Core.Interfaces;

public interface IFileStorageService
{
    /// <summary>
    /// Uploads a file to the storage system
    /// </summary>
    /// <param name="fileStream">The file stream to upload</param>
    /// <param name="remotePath">The remote path where the file should be stored (e.g., "userId/filename.pdf")</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The full path/URL of the uploaded file</returns>
    Task<string> UploadFileAsync(Stream fileStream, string remotePath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads a file from the storage system
    /// </summary>
    /// <param name="remotePath">The remote path of the file to download</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The file stream</returns>
    Task<Stream> DownloadFileAsync(string remotePath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a file from the storage system
    /// </summary>
    /// <param name="remotePath">The remote path of the file to delete</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task DeleteFileAsync(string remotePath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a file exists in the storage system
    /// </summary>
    /// <param name="remotePath">The remote path of the file to check</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if the file exists, false otherwise</returns>
    Task<bool> FileExistsAsync(string remotePath, CancellationToken cancellationToken = default);
}
