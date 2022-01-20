using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using WebApiJwt.IdentityApp;
using WebApiJwt.Models;

namespace WebApiJwt.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Authenticate : ControllerBase
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;

        public Authenticate(UserManager<ApplicationUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if(userExists != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Already Exists" });
            }

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if(!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status ="Error", Message = result.ToString()});
            }
            return Ok(new Response { Status = "Success", Message = "User Created Successfully" });
        }


        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                foreach(var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));

                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:ValidIssuer"],
                    audience: _configuration["Jwt:ValidAudience"],
                    expires: DateTime.Now.AddHours(5),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );

                return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token), expiration = token.ValidTo });
            };
            return Unauthorized();
        }

        [HttpPost]
        [Route("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
        {
            var user = _userManager.FindByNameAsync(model.Username);
            if(user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "User does not exists" });
            }
            if(string.Compare(model.NewPassword, model.ConfirmNewPassword) != 0)
            {
                return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "The new password and confirm new password does not match!" });
            }

            var result = await _userManager.ChangePasswordAsync(await user, model.CurrentPassword, model.NewPassword);
            if(!result.Succeeded)
            {
                var errors = new List<string>();

                foreach(var error in result.Errors)
                {
                    errors.Add(error.Description);
                }
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = String.Join(",", errors) });
            }

            return Ok(new Response { Status = "Success", Message = "Password Changed Successfully" });
        }

        [HttpPost]
        [Route("reset-password-token")]
        public async Task<IActionResult> ResetPasswordToken([FromBody] ResetPasswordTokenModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if(user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "User does not exists!" });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            //return token
            return Ok(new { token = token });
        }

        [HttpPost]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if(user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message= "User does not exists!"});
            }
            if(string.Compare(model.NewPassword, model.ConfirmNewPassword) != 0)
            {
                return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "The new password and confirm new password does not match!" });
            }
            if(!string.IsNullOrEmpty(model.Token))
            {
                return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "Invalid Token" });
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if(!result.Succeeded)
            {
                var errors = new List<string>();

                foreach(var error in result.Errors)
                {
                    errors.Add(error.Description);
                }
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = string.Join(",", errors) });
            }

            return Ok(new Response { Status = "Success", Message = "Password Reset Successfully" });
        }


    }
}
