using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.DTOs;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;

namespace DatingApp.API.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class AuthController : ControllerBase
  {
    private readonly IAuthRepository _repo;
    private readonly IConfiguration _config;
    public AuthController(IAuthRepository repo, IConfiguration config)
    {
      _config = config;
      _repo = repo;

    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(UserForRegisterDTO userForRegisterDTO)
    {

      userForRegisterDTO.Username = userForRegisterDTO.Username.ToLower();
      if (await _repo.UserExists(userForRegisterDTO.Username))
      {
        return BadRequest("Username already exists");
      }

      var userToCreate = new User
      {
        Username = userForRegisterDTO.Username
      };

      var createdUser = await _repo.Register(userToCreate, userForRegisterDTO.Password);

      return StatusCode(201);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(UserForLoginDTO userForLoginDTO)
    {

      var userFromRepo = await _repo.Login(userForLoginDTO.Username.ToLower(), userForLoginDTO.Password);

      if (userFromRepo == null)
        return Unauthorized();

      var claims = new[] {
            new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
            new Claim(ClaimTypes.Name, userFromRepo.Username)
        };

      var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

      var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

      var token = new JwtSecurityToken(
        issuer:"localhost",
        audience:"localhost",
        claims:claims,
        expires:DateTime.Now.AddDays(1),
        signingCredentials:creds
      );

      return Ok(new {
          token = new JwtSecurityTokenHandler().WriteToken(token)
      });

    }

    
  }
}