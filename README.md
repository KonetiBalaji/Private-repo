# TurbineAero - Comprehensive Turbine Management System

A modern, secure authentication system with OTP verification for turbine management and monitoring platform.

## 🚀 Features

### Authentication & Security
- **Registration with OTP Verification**: Email and SMS OTP verification
- **Two-Factor Authentication**: Email OTP, SMS OTP, and Authenticator App support
- **Password Management**: Forgot password, reset password, and change password flows
- **JWT Token Authentication**: Secure API access with token management
- **ASP.NET Core Identity**: Full user management with role-based security

### User Interface
- **Bootstrap 5 UI**: Modern, responsive design
- **Razor Pages**: Server-side rendering with client-side enhancements
- **Real-time Notifications**: Toast notifications for user feedback
- **Dashboard**: Comprehensive turbine monitoring and management

### Backend Services
- **Email Service**: MailKit integration for email notifications
- **SMS Service**: Twilio integration for SMS OTP
- **OTP Service**: Secure 6-digit OTP generation and verification
- **Entity Framework Core**: SQL Server database with migrations

## 🏗️ Project Structure

```
TurbineAero/
├── TurbineAero.sln
├── src/
│   ├── TurbineAero.Web/        # Razor Pages (Bootstrap 5 UI)
│   ├── TurbineAero.API/        # REST controllers (Auth + OTP + Password)
│   ├── TurbineAero.Core/       # DTOs, interfaces, constants
│   ├── TurbineAero.Data/       # EF Core (SQL Server + Identity)
│   └── TurbineAero.Services/   # Email/SMS/OTP logic
└── tests/
    └── TurbineAero.Tests/      # xUnit unit + integration tests
```

## 🛠️ Setup Instructions

### Prerequisites
- .NET 8.0 SDK
- SQL Server (LocalDB or full instance)
- Visual Studio 2022 or VS Code
- Email service account (Gmail, SendGrid, etc.)
- Twilio account for SMS

### 1. Clone and Build
```bash
git clone <repository-url>
cd TurbineAero
dotnet restore
dotnet build
```

### 2. Database Setup
```bash
# Navigate to API project
cd src/TurbineAero.API

# Create and run migrations
dotnet ef migrations add InitialCreate
dotnet ef database update
```

### 3. Configuration

#### API Configuration (`src/TurbineAero.API/appsettings.json`)
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=TurbineAeroDb;Trusted_Connection=true;MultipleActiveResultSets=true"
  },
  "Jwt": {
    "SecretKey": "YourSuperSecretKeyThatIsAtLeast32CharactersLong!",
    "Issuer": "TurbineAero",
    "Audience": "TurbineAeroUsers"
  },
  "Email": {
    "SmtpHost": "smtp.gmail.com",
    "SmtpPort": "587",
    "Username": "your-email@gmail.com",
    "Password": "your-app-password",
    "FromAddress": "noreply@turbineaero.com"
  },
  "Twilio": {
    "AccountSid": "your-twilio-account-sid",
    "AuthToken": "your-twilio-auth-token",
    "FromPhoneNumber": "+1234567890"
  }
}
```

#### Web Configuration (`src/TurbineAero.Web/appsettings.json`)
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=TurbineAeroDb;Trusted_Connection=true;MultipleActiveResultSets=true"
  },
  "Email": {
    "SmtpHost": "smtp.gmail.com",
    "SmtpPort": "587",
    "Username": "your-email@gmail.com",
    "Password": "your-app-password",
    "FromAddress": "noreply@turbineaero.com"
  },
  "Twilio": {
    "AccountSid": "your-twilio-account-sid",
    "AuthToken": "your-twilio-auth-token",
    "FromPhoneNumber": "+1234567890"
  }
}
```

### 4. Email Setup (Gmail)
1. Enable 2-Factor Authentication on your Gmail account
2. Generate an App Password:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate password for "Mail"
3. Use the app password in configuration

### 5. Twilio Setup
1. Create a Twilio account
2. Get your Account SID and Auth Token from the console
3. Purchase a phone number for SMS
4. Update configuration with your credentials

### 6. Run the Application

#### API Server
```bash
cd src/TurbineAero.API
dotnet run
# API will be available at https://localhost:7001
```

#### Web Application
```bash
cd src/TurbineAero.Web
dotnet run
# Web app will be available at https://localhost:7000
```

## 🔐 Authentication Flow

### Registration Process
1. User fills registration form (First Name, Last Name, Email, Phone, Password)
2. System generates 6-digit OTPs for email and phone
3. OTPs are sent via email (MailKit) and SMS (Twilio)
4. User enters both OTPs in verification modal
5. Upon successful verification, account is activated
6. User can now sign in

### Login Process
1. User enters username/email and password
2. System validates credentials via ASP.NET Identity
3. If 2FA is enabled, user selects verification method
4. JWT token is generated upon successful authentication
5. User is redirected to dashboard

### Password Reset Flow
1. User clicks "Forgot Password" on login page
2. Enters registered email address
3. System generates reset token (15 min expiry)
4. Reset link is sent via email
5. User clicks link and enters new password
6. Password is updated via UserManager

## 🧪 Testing

### Run Unit Tests
```bash
cd tests/TurbineAero.Tests
dotnet test
```

### Test Coverage
- OTP generation and verification
- Email service functionality
- SMS service integration
- Authentication flows
- Password management

## 📱 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/verify-otp` - OTP verification
- `POST /api/auth/resend-otp` - Resend OTP codes
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout

### Password Management
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token
- `POST /api/auth/change-password` - Change password (authenticated)

## 🔧 Configuration Options

### OTP Settings
- OTP Length: 6 digits
- Expiry Time: 15 minutes
- Max Attempts: 3
- Hash Algorithm: SHA256

### JWT Settings
- Access Token Expiry: 60 minutes
- Refresh Token Expiry: 30 days
- Signing Algorithm: HMACSHA256

### Security Features
- HTTPS redirection
- HSTS headers
- CORS configuration
- Password complexity requirements
- Account lockout protection

## 🚀 Deployment

### Production Considerations
1. Update connection strings for production database
2. Configure proper email service (SendGrid, AWS SES)
3. Set up production Twilio account
4. Configure HTTPS certificates
5. Set up monitoring and logging
6. Configure backup strategies

### Docker Support (Optional)
```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY . .
RUN dotnet restore
RUN dotnet build
EXPOSE 80
ENTRYPOINT ["dotnet", "TurbineAero.Web.dll"]
```

## 📞 Support

For issues and questions:
- Check the logs for detailed error information
- Verify email and SMS service configurations
- Ensure database connectivity
- Check firewall and network settings

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
