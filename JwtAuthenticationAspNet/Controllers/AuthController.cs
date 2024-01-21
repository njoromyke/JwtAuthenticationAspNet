using JwtAuthenticationAspNet.Core.Dtos;
using JwtAuthenticationAspNet.Core.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthenticationAspNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }


        //Route For Seeding Roles
        [HttpPost]
        [Route("seed-roles")]

        public async Task<IActionResult> SeedRoles()
        {
            var seedRoles = await _authService.SeesRolesAsync();

            return Ok(seedRoles);
        }

        //Route -> Register
        [HttpPost]
        [Route("register")]

        public async Task<IActionResult> Register(RegisterDto registerDto)
        {
            var registerResponse = await _authService.RegisterAsync(registerDto);
            if (registerResponse.IsSuccess)
                return Ok(registerResponse);
            return BadRequest(registerResponse);
        }

        //Route -> Login
        [HttpPost]
        [Route("login")]

        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            var loginResponse = await _authService.LoginAsync(loginDto);
            if (loginResponse.IsSuccess)
                return Ok(loginResponse);
            return BadRequest(loginResponse);

        }

        //Route -> Make user-> admin
        [HttpPost]
        [Route("make-admin")]

        public async Task<IActionResult> MakeAdmin(UpdatePermissionDto updatePermissionDto)
        {
            var makeAdminResponse = await _authService.MakeAdminAsync(updatePermissionDto);
            if (makeAdminResponse.IsSuccess)
                return Ok(makeAdminResponse);
            return BadRequest(makeAdminResponse);
        }

        //Route -> Make user-> owner
        [HttpPost]
        [Route("make-owner")]

        public async Task<IActionResult> MakeOwner(UpdatePermissionDto updatePermissionDto)
        {
            var makeOwnerResponse = await _authService.MakeOwnerAsync(updatePermissionDto);
            if (makeOwnerResponse.IsSuccess)
                return Ok(makeOwnerResponse);
            return BadRequest(makeOwnerResponse);
        }

    }
}
