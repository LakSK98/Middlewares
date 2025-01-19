namespace MiddlewareExample.Services.Interfaces
{
    public interface IJWTService
    {
        public string GenerateToken(string username, List<string> roles);
    }
}
