# 🔧 Migration Instructions - UserFiles Table

## ❌ Current Problem
The `UserFiles` table does not exist in your database, causing:
- "Invalid object name 'UserFiles'" errors
- File uploads failing
- Dashboard unable to load files

## ✅ Solution Options

### Option 1: Using Entity Framework (Recommended)

**Step 1:** Open a **NEW** Command Prompt or PowerShell window (not the one running your app)

**Step 2:** Navigate to the Web project:
```bash
cd E:\Private-repo\src\TurbineAero.Web
```

**Step 3:** Run the migration:
```bash
dotnet ef database update
```

**Expected Output:**
```
Applying migration '20251111000001_AddUserFiles'.
Done.
```

**Step 4:** Restart your application

---

### Option 2: Using SQL Script (If EF doesn't work)

**Step 1:** Open SQL Server Management Studio (SSMS)

**Step 2:** Connect to your database:
- Server: `localhost\SQLEXPRESS` (or your server name)
- Database: `TurbineAeroDb` (from your connection string)

**Step 3:** Open the file `create-userfiles-table.sql` in this directory

**Step 4:** Execute the script (F5 or Execute button)

**Step 5:** Verify the table was created:
```sql
SELECT * FROM UserFiles;
```

**Step 6:** Restart your application

---

### Option 3: Using Visual Studio Package Manager Console

**Step 1:** Open Visual Studio

**Step 2:** Go to: **Tools** → **NuGet Package Manager** → **Package Manager Console**

**Step 3:** Set Default project to: `TurbineAero.Web`

**Step 4:** Run:
```powershell
Update-Database
```

---

## 🔍 Verify Migration Was Applied

After running any of the above options, verify the table exists:

**In SQL Server:**
```sql
SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'UserFiles';
```

**Or check the columns:**
```sql
SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'UserFiles';
```

You should see:
- Id (int, primary key)
- UserId (nvarchar(450))
- FileName (nvarchar(500))
- OriginalFileName (nvarchar(500))
- FilePath (nvarchar(1000))
- FileSize (bigint)
- ContentType (nvarchar(100))
- UploadedAt (datetime2)

---

## 🚀 After Migration

1. **Stop** your running application (Ctrl+C)
2. **Restart** it:
   ```bash
   cd E:\Private-repo\src\TurbineAero.Web
   dotnet run
   ```
3. **Test** file upload at: https://localhost:7001/Dashboard

---

## ❓ Troubleshooting

### "dotnet ef" command not found
Install EF Core tools:
```bash
dotnet tool install --global dotnet-ef
```

### "No migrations found"
The migration file exists at:
`src/TurbineAero.Web/Migrations/20251111000001_AddUserFiles.cs`

If EF can't find it, use Option 2 (SQL Script) instead.

### Connection string issues
Check your `appsettings.json`:
```json
"ConnectionStrings": {
  "DefaultConnection": "Server=localhost\\SQLEXPRESS;Database=TurbineAeroDb;..."
}
```

Make sure:
- SQL Server is running
- Database name matches
- You have permissions to create tables

---

## ✅ Success Indicators

After successful migration:
- ✅ No more "Invalid object name 'UserFiles'" errors
- ✅ Dashboard loads without errors
- ✅ File uploads work
- ✅ Files appear in the "Uploaded Files" section
