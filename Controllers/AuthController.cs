using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using NetCore.Data;
using NetCore.Models;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly WebAPIContext _webAPIContext;
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration, WebAPIContext context)
        {
            _configuration = configuration;
            _webAPIContext = context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserRegisterDTO request)
        {
            if (await _webAPIContext.Users.AnyAsync(p => p.Email == request.Email))
            {
                return BadRequest("Email already exists");
            }

            byte[] passwordHash, passwordSalt;
            CreatePasswordHash(request.Password, out passwordHash, out passwordSalt);

            var user = new User
            {
                Email = request.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                PhoneNumber = request.PhoneNumber,
                DOB = request.DOB
            };

            _webAPIContext.Users.Add(user);

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                await _webAPIContext.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                ModelState.AddModelError("", "Unable to save changes. " +
                    "Please try again, or contact your system administrator.");
            }

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserLoginDTO request)
        {
            var user = await _webAPIContext.Users.FirstOrDefaultAsync(x => x.Email == request.Email);
            if (user == null)
            {
                return BadRequest("User not found");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password");
            }

            string token = CreateToken(user);

            return Ok(token);
        }

        //private string CreateToken(User user)
        //{
        //    var claims = new List<Claim>
        //    {
        //        new Claim(ClaimTypes.NameIdentifier, user.Email)
        //    };

        //    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
        //        _configuration.GetSection("AppSettings:Token").Value));

        //    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        //    var tokenOptions = new JwtSecurityToken(
        //        claims: claims,
        //        expires: DateTime.Now.AddDays(1),
        //        signingCredentials: credentials
        //    );

        //    var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

        //    return token;
        //}

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, user.Email)
    };

            string tokenKey = _configuration.GetSection("AppSettings:Token").Value;
            byte[] keyBytes = Encoding.UTF8.GetBytes(tokenKey);
            var key = new SymmetricSecurityKey(keyBytes);

            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }


        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
