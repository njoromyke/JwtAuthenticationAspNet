using JwtAuthenticationAspNet.Core.Dtos;
using JwtAuthenticationAspNet.Core.Entities;
using JwtAuthenticationAspNet.Core.Interfaces;
using JwtAuthenticationAspNet.Core.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthenticationAspNet.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
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

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<AuthServiceResponseDto> SeesRolesAsync()
        {
            bool isOwnerRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.Owner);
            bool isAdminRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.Admin);
            bool isUserRoleExist = await _roleManager.RoleExistsAsync(StaticUserRoles.User);

            if (isOwnerRoleExist && isAdminRoleExist && isUserRoleExist)
            {
                return new AuthServiceResponseDto
                {
                    IsSuccess = true,
                    Message = "Roles Already Seeded"
                };
            }

            var admin = new IdentityRole(StaticUserRoles.Admin);
            var owner = new IdentityRole(StaticUserRoles.Owner);
            var user = new IdentityRole(StaticUserRoles.User);


            await _roleManager.CreateAsync(admin);
            await _roleManager.CreateAsync(owner);
            await _roleManager.CreateAsync(user);
            return new AuthServiceResponseDto()
            {
                IsSuccess = true,
                Message = "Roles Seeded"
            };
        }
        public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            var isUserExist = await _userManager.FindByNameAsync(registerDto.UserName);
            if (isUserExist != null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSuccess = false,
                    Message = "User Already Exist"
                };
            }

            var user = new ApplicationUser()
            {
                UserName = registerDto.UserName,
                Email = registerDto.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName

            };

            var createUserResult = await _userManager.CreateAsync(user, registerDto.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed: ";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += error.Description + " ";
                }
                return new AuthServiceResponseDto()
                {
                    IsSuccess = false,
                    Message = errorString
                };
            }

            //Add Default Role
            await _userManager.AddToRoleAsync(user, StaticUserRoles.User);

            return new AuthServiceResponseDto()
            {
                IsSuccess = true,
                Message = "User Created Successfully"
            };
        }

        public async Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);

            if (user == null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSuccess = false,
                    Message = "Invalid Credentials"
                };
            }

            var isPasswordValid = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!isPasswordValid)
            {
                return new AuthServiceResponseDto()
                {
                    IsSuccess = false,
                    Message = "Invalid Credentials"
                };
            }

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JwtId", Guid.NewGuid().ToString()),
                new Claim("FistName", user.FirstName),
                new Claim("LastName", user.LastName),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);

            return new AuthServiceResponseDto()
            {
                IsSuccess = true,
                Message = token
            };
        }

        public async Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user == null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSuccess = false,
                    Message = "Invalid UserName"
                };
            }

            await _userManager.AddToRoleAsync(user, StaticUserRoles.Admin);
            return new AuthServiceResponseDto()
            {
                IsSuccess = false,
                Message = "User is now an admin"
            };
        }

        public async Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user == null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSuccess = false,
                    Message = "Invalid UserName"
                };
            }

            await _userManager.AddToRoleAsync(user, StaticUserRoles.Owner);
            return new AuthServiceResponseDto()
            {
                IsSuccess = false,
                Message = "User is now an owner"
            };
        }
    }
}
