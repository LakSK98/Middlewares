using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MiddlewareExample.Middlewares;
using MiddlewareExample.Services.Interfaces;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IJWTService _jWTService;

    public AuthController(IJWTService jWTService)
    {
        _jWTService = jWTService;
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // Validate user credentials (hardcoded for demo purposes)
        if (request.Username == "test" && request.Password == "password")
        {
            var token = _jWTService.GenerateToken(request.Username, new List<string> { "User" });
            return Ok(new { Token = token });
        }

        return Unauthorized();
    }

    [Authorize]
    [RequiredPermission("AdminAccess")]
    [HttpGet("protected")]
    public IActionResult ProtectedEndpoint()
    {
        return Ok(new { Message = "This is a protected endpoint." });
    }
}

public class LoginRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}
