using JwtAuthenticationAspNet.Core.OtherObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthenticationAspNet.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };


        [HttpGet]
        [Route("Get")]
        public IActionResult Get()
        {
            return Ok(Summaries);
        }
        
        [HttpGet]
        [Route("GetUsersRole")]
        [Authorize(Roles = StaticUserRoles.User)]
        public IActionResult GetUsersRole()
        {
            return Ok(Summaries);
        }
        
        [HttpGet]
        [Route("GetAdminRole")]
        [Authorize(Roles = StaticUserRoles.Admin)]
        public IActionResult GetAdminRole()
        {
            return Ok(Summaries);
        } 

        [HttpGet]
        [Route("GetOwnerRole")]
        [Authorize(Roles = StaticUserRoles.Owner)]
        public IActionResult GetOwnerRole()
        {
            return Ok(Summaries);
        }
    }
}
