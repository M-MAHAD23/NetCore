namespace NetCore.Models
{
    public class User
    {
        public int Id { get; set; }

        public string Username { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;

        public string Email { get; set; } = string.Empty;

        public string PhoneNumber { get; set; } = string.Empty;
        public DateTime DOB { get; set; }

        public string Avatar { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }

        public DateTime CreatedDate { get; set; }

        public DateTime UpdatedDate { get; set; }


    }
}