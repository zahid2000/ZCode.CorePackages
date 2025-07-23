namespace ZCode.Core.Application.HealthChecks;

public interface IHealthCheck
{
    Task<HealthCheckResult> CheckHealthAsync(CancellationToken cancellationToken = default);
}

public class HealthCheckResult
{
    public bool IsHealthy { get; set; }
    public string? Description { get; set; }
    public Dictionary<string, object>? Data { get; set; }

    public static HealthCheckResult Healthy(string? description = null, Dictionary<string, object>? data = null)
        => new() { IsHealthy = true, Description = description, Data = data };

    public static HealthCheckResult Unhealthy(string? description = null, Dictionary<string, object>? data = null)
        => new() { IsHealthy = false, Description = description, Data = data };
}
