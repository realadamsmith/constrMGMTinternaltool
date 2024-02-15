using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using csServer.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

// Add other using statements as needed for your project
[ApiController]
[Route("[controller]")]

public class TestController : ControllerBase
{
    [HttpGet]
    public ActionResult GetTest()
    {
        Console.WriteLine("Got bro");
        return Ok(new { message = "This is a test response from your backend" });
    }
}
public class AuthController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly IConfiguration _configuration;

    public AuthController(ApplicationDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }

    [HttpPost("register")]
     public async Task<ActionResult> Register([FromBody] UserDto userDto)
    {
        var userExists = await _context.Users.AnyAsync(u => u.Username == userDto.Username);
        if (userExists) return BadRequest("Username already exists");

        CreatePasswordHash(userDto.Password, out byte[] passwordHash);

        var user = new User
        {
            Username = userDto.Username,
            PasswordHash = Convert.ToBase64String(passwordHash)
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return Ok("User created successfully");
    }

    [HttpPost("login")]
 public async Task<ActionResult> Login([FromBody] UserDto userDto)
    {
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == userDto.Username);
        if (user == null || !VerifyPasswordHash(userDto.Password, Convert.FromBase64String(user.PasswordHash)))
        {
            return Unauthorized("Invalid username or password");
        }

        var token = CreateToken(user);
        return Ok(new { AccessToken = token });
    }

    private void CreatePasswordHash(string password, out byte[] passwordHash)
    {
        using var hmac = new HMACSHA512();
        passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
    }

    private bool VerifyPasswordHash(string password, byte[] storedHash)
    {
        using var hmac = new HMACSHA512();
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        return computedHash.SequenceEqual(storedHash);
    }

    private string CreateToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.Now.AddHours(1),
            SigningCredentials = creds
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }
}
