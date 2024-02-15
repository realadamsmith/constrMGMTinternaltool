public class User
{
    public int Id { get; set; }
    public string? Username { get; set; } // Mark as nullable
    public string? PasswordHash { get; set; } // Mark as nullable
}


namespace csServer.Models
{
    public class UserDto
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
    }
}
