namespace NetCore.Models
{
    public class UserUpdateDTO
    {
        public string UserName { get; set; } = string.Empty;

        public string Name { get; set; } = string.Empty;

        public string Avatar { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;

        public string PhoneNumber { get; set; } = string.Empty;
        public DateTime DOB { get; set; }
        DateTime CreatedDate { get; set; }
    }
}