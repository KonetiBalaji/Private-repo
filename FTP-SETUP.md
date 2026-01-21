# FTP File Storage Setup Guide

## Overview

The Dashboard now supports FTP-based file storage, allowing you to store uploaded files on a remote FTP server instead of locally on the web server. This provides better scalability and separation of concerns.

## Architecture

- **IFileStorageService**: Interface for file storage operations
- **FtpFileStorageService**: FTP implementation
- **LocalFileStorageService**: Local file system fallback (optional)

## Configuration

### 1. FTP Configuration (appsettings.json)

Add the following configuration to `src/TurbineAero.Web/appsettings.json`:

```json
{
  "Ftp": {
    "Host": "ftp.example.com",
    "Username": "your-ftp-username",
    "Password": "your-ftp-password",
    "BasePath": "/uploads",
    "UseSsl": false
  }
}
```

### 2. Configuration Options

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| `Host` | FTP server hostname or IP address | Yes | - |
| `Username` | FTP username | Yes | - |
| `Password` | FTP password | Yes | - |
| `BasePath` | Base directory path on FTP server | No | `/uploads` |
| `UseSsl` | Enable FTPS (secure FTP) | No | `false` |

### 3. Service Registration

The FTP service is registered in `Program.cs`:

```csharp
builder.Services.AddScoped<IFileStorageService, FtpFileStorageService>();
```

To use local storage instead, change to:

```csharp
builder.Services.AddScoped<IFileStorageService, LocalFileStorageService>();
```

## FTP Server Setup

### Windows (IIS FTP)

1. Install IIS FTP Server feature
2. Create FTP site
3. Configure authentication (Basic or Windows)
4. Set permissions for upload directory

### Linux (vsftpd)

```bash
# Install vsftpd
sudo apt-get install vsftpd

# Configure /etc/vsftpd.conf
listen=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO

# Restart service
sudo systemctl restart vsftpd
```

### Cloud FTP Services

- **AWS Transfer Family**: Managed FTP service
- **Azure Files**: SMB/NFS with FTP gateway
- **Google Cloud Storage**: With FTP adapter
- **FileZilla Server**: Free FTP server for Windows/Linux

## Security Considerations

### 1. Use FTPS (FTP over SSL/TLS)

Set `UseSsl: true` in configuration for encrypted connections:

```json
{
  "Ftp": {
    "UseSsl": true
  }
}
```

### 2. Secure Credentials

- **Never commit** FTP credentials to version control
- Use **Azure Key Vault**, **AWS Secrets Manager**, or **Environment Variables**
- Store credentials in `appsettings.json` (already in .gitignore)

### 3. Network Security

- Use firewall rules to restrict FTP access
- Consider VPN for additional security
- Use IP whitelisting if possible

### 4. File Permissions

- Set appropriate directory permissions on FTP server
- Use separate user accounts with minimal required permissions
- Enable chroot to restrict users to their directories

## Testing FTP Connection

### Using FileZilla Client

1. Open FileZilla
2. Enter FTP server details:
   - Host: `ftp.example.com`
   - Username: `your-username`
   - Password: `your-password`
   - Port: `21` (or `990` for FTPS)
3. Click "Quickconnect"
4. Test upload/download

### Using Command Line (Linux/Mac)

```bash
# Test FTP connection
ftp ftp.example.com

# Or with credentials
ftp -u username:password ftp.example.com
```

### Using PowerShell (Windows)

```powershell
# Test FTP connection
$ftp = [System.Net.FtpWebRequest]::Create("ftp://ftp.example.com/")
$ftp.Credentials = New-Object System.Net.NetworkCredential("username", "password")
$ftp.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
$response = $ftp.GetResponse()
```

## Troubleshooting

### Common Issues

1. **Connection Timeout**
   - Check firewall settings
   - Verify FTP server is running
   - Check network connectivity

2. **Authentication Failed**
   - Verify username/password
   - Check user permissions on FTP server
   - Ensure user account exists

3. **Directory Creation Failed**
   - Check write permissions
   - Verify base path exists
   - Check disk space

4. **SSL/TLS Errors**
   - For self-signed certificates, the service ignores certificate validation
   - In production, use valid SSL certificates
   - Consider using `UseSsl: false` for testing

### Debugging

Enable detailed logging in `appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "TurbineAero.Services.FtpFileStorageService": "Debug"
    }
  }
}
```

## File Path Structure

Files are stored with the following structure on the FTP server:

```
/uploads/
  └── {userId}/
      ├── {guid}_filename1.pdf
      ├── {guid}_filename2.pdf
      └── ...
```

The `FilePath` in the database stores the full FTP URL or relative path:
- FTP URL: `ftp://ftp.example.com/uploads/userId/guid_filename.pdf`
- Relative path: `userId/guid_filename.pdf`

## Migration from Local Storage

If you have existing files in local storage:

1. **Backup existing files**
2. **Upload to FTP server** using a migration script
3. **Update database** `FilePath` values to FTP paths
4. **Switch service registration** to `FtpFileStorageService`

## Performance Considerations

- **Connection Pooling**: The service creates new connections for each operation
- **Large Files**: For files > 50MB, consider chunked uploads
- **Concurrent Uploads**: FTP server may limit concurrent connections
- **Network Latency**: Consider FTP server location relative to application

## Alternative: Hybrid Approach

You can implement a hybrid service that:
- Uses FTP for production
- Falls back to local storage if FTP is unavailable
- Automatically migrates files from local to FTP

## Support

For issues or questions:
1. Check application logs
2. Verify FTP server logs
3. Test FTP connection independently
4. Review error messages in Dashboard
