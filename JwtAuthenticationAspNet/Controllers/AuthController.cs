using JwtAuthenticationAspNet.Core.Dtos;
using JwtAuthenticationAspNet.Core.OtherObjects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

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
    }
}
