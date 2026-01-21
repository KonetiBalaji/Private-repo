# TurbineAero Application Setup Guide

## Prerequisites
- .NET 8.0 SDK installed
- SQL Server (local or remote)
- Database connection configured in `appsettings.json`

## Step 1: Database Migration

Before running the application, you need to apply the database migrations:

```bash
cd src/TurbineAero.Web
dotnet ef database update
```

This will create all necessary database tables including the new `UserFiles` table.

## Step 2: Run the Application

You have several options to run the application:

### Option 1: Run Both Applications Together (Recommended)

Use the combined launcher:
```bash
run-all.bat
```

This will start both the API and Web applications in separate windows.

### Option 2: Run Applications Separately

**Terminal 1 - Start API:**
```bash
start-api.bat
```
or
```bash
cd src\TurbineAero.API
dotnet run
```

**Terminal 2 - Start Web:**
```bash
start-web.bat
```
or
```bash
cd src\TurbineAero.Web
dotnet run
```

### Option 3: Manual Start

**API Server:**
```bash
cd src\TurbineAero.API
dotnet run --urls "https://localhost:7003"
```

**Web Application:**
```bash
cd src\TurbineAero.Web
dotnet run --urls "https://localhost:7001"
```

## Application URLs

Once running, access the applications at:

- **Web Application:** https://localhost:7001
- **API Server:** https://localhost:7003

## Features

After logging in, you can:
- Upload multiple PDF files
- View uploaded files
- Download files
- Delete files

## Troubleshooting

### Database Migration Issues

If you get "Invalid object name 'UserFiles'" error:
1. Make sure you've run `dotnet ef database update` in the `src/TurbineAero.Web` directory
2. Verify your database connection string in `appsettings.json`

### Port Already in Use

If you get port conflict errors:
- Check if another instance is already running
- Modify the URLs in `Program.cs` or use different ports

### Missing EF Core Tools

If `dotnet ef` command is not found:
```bash
dotnet tool install --global dotnet-ef
```
