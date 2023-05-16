namespace NetCore.Models
{
    public class UserRegisterDTO
    {
        public string Email { get; set; } = string.Empty;

        public string PhoneNumber { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public DateTime DOB { get; set; }
        DateTime CreatedDate { get; set; }
    }
}