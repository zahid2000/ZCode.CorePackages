# ZCode.CorePackages

A comprehensive set of .NET Core libraries implementing Clean Architecture principles for enterprise applications.

## 📦 Packages

### Core.Domain
Base domain layer providing:
- **Base Entities** with audit trails and soft delete support
- **Value Objects** with equality comparison
- **Domain Events** with MediatR integration
- **Specifications** pattern for complex queries
- **Common Value Objects** (Email, etc.)

### Core.Application
Application layer with CQRS and cross-cutting concerns:
- **MediatR Pipeline Behaviors** (Validation, Caching, Performance, Transaction)
- **Result Pattern** for error handling
- **DTOs and Responses** for data transfer
- **Security Abstractions** for user context
- **Health Check** interfaces

### Core.Persistence
Data access layer with Entity Framework Core:
- **Generic Repository Pattern** with async/sync operations
- **Unit of Work** pattern
- **Dynamic Queries** with filtering and sorting
- **Pagination** support
- **Soft Delete** with cascade operations
- **Audit Interceptors** for tracking changes
- **Domain Events** publishing

### Core.CrossCuttingConcerns.Exception
Exception handling foundation:
- **Custom Exception Types** (Business, Validation, Authorization, NotFound)
- **Exception Handlers** with proper abstraction

### Core.CrossCuttingConcerns.Exception.WebApi
Web API exception handling:
- **Global Exception Middleware**
- **Problem Details** responses
- **HTTP Status Code** mapping

## 🚀 Quick Start

### 1. Install Packages
```bash
dotnet add package ZCode.Core.Domain
dotnet add package ZCode.Core.Application
dotnet add package ZCode.Core.Persistence
dotnet add package ZCode.Core.CrossCuttingConcerns.Exception.WebApi
```

### 2. Configure Services
```csharp
// Program.cs
builder.Services.AddApplicationServices(Assembly.GetExecutingAssembly());
builder.Services.AddPersistenceServices<YourDbContext>();
```

### 3. Configure Middleware
```csharp
// Program.cs
app.ConfigureCustomExceptionMiddleware();
```

## 🏗️ Architecture

This package follows Clean Architecture principles:
- **Domain Layer**: Core business logic and rules
- **Application Layer**: Use cases and application services
- **Infrastructure Layer**: Data access and external services
- **Presentation Layer**: Controllers and UI

## ✨ Features

- ✅ **Clean Architecture** compliant
- ✅ **CQRS** with MediatR
- ✅ **Domain Events**
- ✅ **Specification Pattern**
- ✅ **Repository & Unit of Work**
- ✅ **Soft Delete** with cascade
- ✅ **Audit Trail**
- ✅ **Dynamic Queries**
- ✅ **Pagination**
- ✅ **Caching** pipeline
- ✅ **Validation** pipeline
- ✅ **Performance** monitoring
- ✅ **Global Exception** handling
- ✅ **Result Pattern**
- ✅ **Value Objects**

## 📄 License

MIT License - see [LICENSE.txt](LICENSE.txt) for details.