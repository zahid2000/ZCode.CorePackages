namespace ZCode.Core.Security.Models;

public class EncryptionOptions
{
    public string Key { get; set; } = string.Empty;
    public string IV { get; set; } = string.Empty;
}
