using System.ComponentModel.DataAnnotations;

namespace JwtAuthenticationAspNet.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "Username is required")]
        public string UserName { get; set; }


    }
}