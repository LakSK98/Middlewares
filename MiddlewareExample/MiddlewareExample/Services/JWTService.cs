using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MiddlewareExample.Services.Interfaces;
using MiddlewareExample.Settings;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MiddlewareExample.Services
{
    public class JWTService : IJWTService
    {
        private readonly JWTSettings _jwtSettings;
        public JWTService(IOptions<JWTSettings> jwtSettings) 
        {
            _jwtSettings = jwtSettings.Value;
        }
        public string GenerateToken(string username, List<string> roles)
        {

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, username),
            new Claim("Role", roles[0]),
        };

            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var token = new JwtSecurityToken(
                _jwtSettings.Issuer,
                _jwtSettings.Audience,
                claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
