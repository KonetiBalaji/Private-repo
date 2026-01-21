-- ========================================
-- Create UserFiles Table Manually
-- ========================================
-- Run this script in SQL Server Management Studio
-- or execute it directly against your database
-- ========================================

-- Check if table already exists
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[UserFiles]') AND type in (N'U'))
BEGIN
    -- Create UserFiles table
    CREATE TABLE [dbo].[UserFiles] (
        [Id] int IDENTITY(1,1) NOT NULL,
        [UserId] nvarchar(450) NOT NULL,
        [FileName] nvarchar(500) NOT NULL,
        [OriginalFileName] nvarchar(500) NOT NULL,
        [FilePath] nvarchar(1000) NOT NULL,
        [FileSize] bigint NOT NULL,
        [ContentType] nvarchar(100) NOT NULL,
        [UploadedAt] datetime2 NOT NULL,
        CONSTRAINT [PK_UserFiles] PRIMARY KEY ([Id])
    );

    -- Create foreign key to AspNetUsers
    ALTER TABLE [dbo].[UserFiles]
    ADD CONSTRAINT [FK_UserFiles_AspNetUsers_UserId]
    FOREIGN KEY ([UserId]) REFERENCES [dbo].[AspNetUsers] ([Id])
    ON DELETE CASCADE;

    -- Create indexes
    CREATE INDEX [IX_UserFiles_UserId] ON [dbo].[UserFiles] ([UserId]);
    CREATE INDEX [IX_UserFiles_UploadedAt] ON [dbo].[UserFiles] ([UploadedAt]);

    PRINT 'UserFiles table created successfully!';
END
ELSE
BEGIN
    PRINT 'UserFiles table already exists.';
END

-- Verify the table was created
SELECT 
    TABLE_NAME,
    COLUMN_NAME,
    DATA_TYPE,
    CHARACTER_MAXIMUM_LENGTH
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = 'UserFiles'
ORDER BY ORDINAL_POSITION;
