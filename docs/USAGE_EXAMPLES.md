# Usage Examples

## Domain Layer Examples

### Creating Entities with Timed Events
```csharp
public class User : AuditableEntity<Guid>
{
    public Email Email { get; private set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }

    private User() { } // EF Core

    public User(Email email, string firstName, string lastName)
    {
        Email = email;
        FirstName = firstName;
        LastName = lastName;

        // Pre-save event - will be published before SaveChanges
        AddDomainEvent(new UserCreatedEvent(Id, email.Value));

        // Post-save event - will be published after SaveChanges
        AddDomainEvent(new UserPersistedEvent(Id, email.Value));
    }
}
```

### Value Objects
```csharp
var email = Email.Create("user@example.com");
var user = new User(email, "John", "Doe");
```

### Specifications
```csharp
public class ActiveUserSpecification : Specification<User>
{
    public override Expression<Func<User, bool>> ToExpression()
    {
        return user => user.DeletedDate == null && user.IsActive;
    }
}

// Usage
var activeUsers = await repository.GetListBySpecificationAsync(
    new ActiveUserSpecification()
);
```

## Application Layer Examples

### CQRS Commands/Queries
```csharp
public class CreateUserCommand : IRequest<Result<UserDto>>, ITransactionalRequest
{
    public string Email { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
}

public class CreateUserCommandHandler : IRequestHandler<CreateUserCommand, Result<UserDto>>
{
    private readonly IAsyncRepository<User, Guid> _userRepository;
    
    public async Task<Result<UserDto>> Handle(CreateUserCommand request, CancellationToken cancellationToken)
    {
        var email = Email.Create(request.Email);
        var user = new User(email, request.FirstName, request.LastName);
        
        await _userRepository.AddAsync(user, cancellationToken);
        
        return Result.Success(new UserDto { Id = user.Id, Email = user.Email });
    }
}
```

### Caching
```csharp
public class GetUserQuery : IRequest<UserDto>, ICachableRequest
{
    public Guid Id { get; set; }
    
    public bool BypassCache { get; set; }
    public string CacheKey => $"User-{Id}";
    public string? CacheGroupKey => "Users";
    public TimeSpan? SlidingExpiration => TimeSpan.FromMinutes(30);
}
```

## Persistence Layer Examples

### Repository Usage
```csharp
// Get with includes
var user = await userRepository.GetAsync(
    predicate: u => u.Id == userId,
    include: u => u.Include(x => x.Orders),
    enableTracking: false
);

// Dynamic queries
var dynamicQuery = new DynamicQuery
{
    Filter = new Filter { Field = "FirstName", Operator = "contains", Value = "John" },
    Sort = new[] { new Sort { Field = "CreatedDate", Dir = "desc" } }
};

var users = await userRepository.GetListByDynamicAsync(dynamicQuery);

// Pagination
var pagedUsers = await userRepository.GetListAsync(
    index: 0, 
    size: 10,
    orderBy: q => q.OrderBy(u => u.FirstName)
);
```

### Unit of Work
```csharp
public class UserService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly IAsyncRepository<User, Guid> _userRepository;
    
    public async Task TransferUsersAsync(List<User> users)
    {
        await _unitOfWork.BeginTransactionAsync();
        
        try
        {
            foreach (var user in users)
            {
                await _userRepository.UpdateAsync(user);
            }
            
            await _unitOfWork.SaveChangesAsync();
            await _unitOfWork.CommitTransactionAsync();
        }
        catch
        {
            await _unitOfWork.RollbackTransactionAsync();
            throw;
        }
    }
}
```

## Configuration Examples

### Startup Configuration
```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddApplicationServices(Assembly.GetExecutingAssembly());
builder.Services.AddPersistenceServices<ApplicationDbContext>();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString)
           .AddInterceptors(
               serviceProvider.GetRequiredService<AuditableEntitySaveChangesInterceptors<Guid>>(),
               serviceProvider.GetRequiredService<DomainEventsInterceptor>()
           ));

var app = builder.Build();

// Configure middleware
app.ConfigureCustomExceptionMiddleware();
```

### DbContext Configuration
```csharp
public class ApplicationDbContext : DbContext
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Register all entities
        modelBuilder.RegisterAllEntities<IEntity<Guid>>(Assembly.GetExecutingAssembly());
        
        // Apply soft delete filter
        modelBuilder.ApplySoftDeleteQueryFilter();

        base.OnModelCreating(modelBuilder);
    }
}
```

## Event Timing Examples

### Pre-Save vs Post-Save Events
```csharp
// Pre-save event - published before SaveChanges
public class UserValidationEvent : DomainEvent, IPreSaveDomainEvent
{
    public Guid UserId { get; }
    public string Email { get; }

    public UserValidationEvent(Guid userId, string email)
    {
        UserId = userId;
        Email = email;
    }
}

// Post-save event - published after SaveChanges
public class UserNotificationEvent : DomainEvent, IPostSaveDomainEvent
{
    public Guid UserId { get; }
    public string Email { get; }

    public UserNotificationEvent(Guid userId, string email)
    {
        UserId = userId;
        Email = email;
    }
}

// Event handler that can trigger nested events
public class UserValidationEventHandler : INotificationHandler<UserValidationEvent>
{
    private readonly IDomainEventPublisher _eventPublisher;

    public async Task Handle(UserValidationEvent notification, CancellationToken cancellationToken)
    {
        // Validate user
        if (await IsEmailDuplicate(notification.Email))
        {
            // Queue another event to be processed after current event
            await _eventPublisher.QueueEventAsync(
                new UserEmailDuplicateEvent(notification.UserId, notification.Email),
                cancellationToken);
        }
    }
}
```

### Nested Event Publishing
```csharp
public class OrderCreatedEventHandler : INotificationHandler<OrderCreatedEvent>
{
    private readonly IDomainEventPublisher _eventPublisher;

    public async Task Handle(OrderCreatedEvent notification, CancellationToken cancellationToken)
    {
        // Process order
        await ProcessOrder(notification.OrderId);

        // Trigger nested events
        await _eventPublisher.QueueEventAsync(
            new InventoryUpdatedEvent(notification.ProductId, notification.Quantity),
            cancellationToken);

        await _eventPublisher.QueueEventAsync(
            new CustomerNotificationEvent(notification.CustomerId, "Order created"),
            cancellationToken);
    }
}
```
