using JwtAuthenticationAspNet.Core.Dtos;

namespace JwtAuthenticationAspNet.Core.Interfaces
{
    public interface IAuthService
    {
        Task<AuthServiceResponseDto> SeesRolesAsync();
        Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto);
        Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto);
        Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto);
        Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto);

    }
}
