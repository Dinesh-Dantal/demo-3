using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PenToPublic.Data;
using PenToPublic.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace PenToPublic.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class RegistrationController : ControllerBase
    {
        private readonly PenToPublicContext _context;
        private readonly IConfiguration _configuration;

        public RegistrationController(PenToPublicContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Registration model)
        {
            if (await _context.Registrations.AnyAsync(r => r.Email == model.Email))
                return BadRequest("Email already registered.");

            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(model.Password);

            var registration = new Registration
            {
                Email = model.Email,
                UserName = model.UserName,
                Password = hashedPassword
            };

            _context.Registrations.Add(registration);
            await _context.SaveChangesAsync();

            // Add user linked to registration
            var user = new User
            {
                RegId = registration.RegId,
                Role = "reader", // Or "author" — you may expose this in the input
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok("Registration successful");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Registration login)
        {
            var userReg = await _context.Registrations.Include(r => r.User)
                .FirstOrDefaultAsync(u => u.Email == login.Email);

            if (userReg == null || !BCrypt.Net.BCrypt.Verify(login.Password, userReg.Password))
                return Unauthorized("Invalid credentials");

            var token = GenerateJwtToken(userReg.User.Role, userReg.Email);

            return Ok(new { token });
        }

        private string GenerateJwtToken(string role, string email)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Email, email),
                new Claim(ClaimTypes.Role, role)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Jwt:ExpiresInMinutes"]!)),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
