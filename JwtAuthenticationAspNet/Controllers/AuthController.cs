using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtAuthenticationAspNet.Core.Dtos;
using JwtAuthenticationAspNet.Core.OtherObjects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthenticationAspNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        //Route For Seeding Roles
        [HttpPost]
        [Route("seed-roles")]

        public async Task<IActionResult> SeedRoles()
        {
            bool isOwnerRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.Owner);
            bool isAdminRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.Admin);
            bool isUserRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.User);

            if (isOwnerRoleExist && isAdminRoleExist && isUserRoleExist)
            {
                return Ok("Roles Already Seeded");
            }

            var admin = new IdentityRole(StaticUserRoles.Admin);
            var owner = new IdentityRole(StaticUserRoles.Owner);
            var user = new IdentityRole(StaticUserRoles.User);


            await _roleManager.CreateAsync(admin);
            await _roleManager.CreateAsync(owner);
            await _roleManager.CreateAsync(user);
            return Ok("Roles Seeded");
        }

        //Route -> Register
        [HttpPost]
        [Route("register")]

        public async Task<IActionResult> Register(RegisterDto registerDto)
        {
            var isUserExist = await _userManager.FindByNameAsync(registerDto.UserName);
            if (isUserExist != null)
            {
                return BadRequest("User Already Exist");
            }

            var user = new IdentityUser()
            {
                UserName = registerDto.UserName,
                Email = registerDto.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var createUserResult = await _userManager.CreateAsync(user, registerDto.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed: ";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += error.Description + " ";
                }
                return BadRequest(errorString);
            }

            //Add Default Role
            await _userManager.AddToRoleAsync(user, StaticUserRoles.User);

            return Ok("User Created Successfully");
        }

        //Route -> Login
        [HttpPost]
        [Route("login")]

        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);

            if (user == null)
            {
                return Unauthorized("Invalid Credentials");
            }

            var isPasswordValid = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!isPasswordValid)
            {
                return Unauthorized("Invalid Credentials");
            }

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JwtId", Guid.NewGuid().ToString()),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);

            return Ok(token);
        }

        private string GenerateNewJsonWebToken(List<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: claims,
                signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;

        }
    }
}
