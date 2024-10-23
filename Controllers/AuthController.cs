using jWtTokenWebApi.Auth;
using jWtTokenWebApi.Interfaces;
using jWtTokenWebApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace jWtTokenWebApi.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]    
    public class AuthController : ControllerBase
    {
        private IOptions<Audience> _settings;
        private readonly IUserService _userService;

        public AuthController(IOptions<Audience> settings, IUserService userService)
        {
            _settings = settings;
            _userService = userService;
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> GetToken([FromBody] AuthRequest authRequest)
        {
            var objAuthResponse = new AuthResponse();
            var key = "LifeisnotSecureSoLoveyouDailyWor";
            try
            {
                if (authRequest.grant_type != "password")
                {
                    objAuthResponse.responsemsg = "grant_type is not valid";
                    objAuthResponse.responsecode="401";
                    return Unauthorized(objAuthResponse);
                }
                else
                {
                    var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                    var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
                    var credentials = Encoding.UTF8.GetString(credentialBytes).Split(new[] { ':' }, 2);
                    var username = credentials[0];
                    var password = credentials[1];
                    if(authRequest.username!= username && authRequest.Password !=password)
                    {
                        objAuthResponse.responsemsg = "your proided auth info is not valid";
                        objAuthResponse.responsecode = "401";
                        return Unauthorized(objAuthResponse);
                    }

                }

                if (!string.IsNullOrEmpty(authRequest.username)  && !string.IsNullOrEmpty(authRequest.Password) )
                {
                    //----------------retrive user role from database------
                    User user = null;
                    user = await _userService.AccessPermission(authRequest.username, authRequest.Password);
                    //-----------------------------------------------------
                    if(user.Username!= authRequest.username)
                    {
                        objAuthResponse.responsemsg = "authentication is not valid";
                        objAuthResponse.responsecode = "401";
                        return Unauthorized(objAuthResponse);
                    }
                    var now = DateTime.UtcNow;

                    var claims = new List<Claim>
                    {
                        new Claim(JwtRegisteredClaimNames.Sub, authRequest.username),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim(JwtRegisteredClaimNames.Iat, now.ToUniversalTime().ToString(), ClaimValueTypes.Integer64)

                    };


                    foreach (string role in user.roles)
                    {
                        claims.Add(new Claim("scope", role));
                    }

                    var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_settings.Value.Secret));

                    var jwt = new JwtSecurityToken(
                        issuer: _settings.Value.Iss,
                        audience: _settings.Value.Aud,
                        claims: claims,
                        notBefore: now,
                        expires: now.Add(TimeSpan.FromMinutes(Convert.ToDouble(_settings.Value.Times))),
                        signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
                    );
                    var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                    objAuthResponse.responsecode = "0";
                    objAuthResponse.expires = DateTime.Now.AddMinutes(60).ToString("ddd, dd MMM yyy HH':'mm':'ss 'GMT'");
                    objAuthResponse.issued = DateTime.Now.ToString("ddd, dd MMM yyy HH':'mm':'ss 'GMT'");
                    objAuthResponse.userName = user.Username;
                    //objAuthResponse.client_id = user.Username;
                    
                    string credentials = $"{user.Username}:{AesEncryption.Encrypt(user.Password, key)}:{objAuthResponse.issued}";
                    objAuthResponse.refresh_token = AesEncryption.Encrypt(credentials, key);

                    objAuthResponse.expires_in = (int)TimeSpan.FromMinutes(Convert.ToDouble(60)).TotalMinutes;
                    objAuthResponse.token_type = "bearer";
                    objAuthResponse.access_token = encodedJwt;
                    objAuthResponse.responsecode = "200";
                    objAuthResponse.responsemsg = "success";

                    return Ok(objAuthResponse);
                }
                else
                {
                    objAuthResponse.access_token = "";
                    objAuthResponse.expires_in = 0;

                    return Unauthorized(objAuthResponse);
                }
            }
            catch (Exception est)
            {
                objAuthResponse.access_token = "";
                objAuthResponse.expires_in = 0;

                return NotFound(objAuthResponse);
            }

        }

        [HttpPost]
        public async Task<IActionResult> RefreshToken([FromBody] AuthRefreshRequest authRefreshRequest)
        {
            var objAuthResponse = new AuthResponse();
            var authRequest =new  AuthRequest();
            var key = "LifeisnotSecureSoLoveyouDailyWor";
            try
            {

                if (string.IsNullOrEmpty(authRefreshRequest.refresh_token))
                {
                    objAuthResponse.responsemsg = "refresh_token is not valid";
                    objAuthResponse.responsecode = "401";
                    return Unauthorized(objAuthResponse);
                }
                else
                {
                    // dycrept authRefreshReques                   
                    var firstString= AesEncryption.Decrypt(authRefreshRequest.refresh_token, key);
                    var credentials = firstString.Split(new[] { ':' }, 3);
                    authRequest.username = credentials[0];
                    authRequest.Password = AesEncryption.Decrypt(credentials[1], key);

                }

                if (!string.IsNullOrEmpty(authRequest.username) && !string.IsNullOrEmpty(authRequest.Password))
                {
                    //----------------retrive user role from database------
                    User user = null;
                    user = await _userService.AccessPermission(authRequest.username, authRequest.Password);
                    //-----------------------------------------------------
                    if (user.Username != authRequest.username)
                    {
                        objAuthResponse.responsemsg = "authentication is not valid";
                        objAuthResponse.responsecode = "401";
                        return Unauthorized(objAuthResponse);
                    }
                    var now = DateTime.UtcNow;

                    var claims = new List<Claim>
                    {
                        new Claim(JwtRegisteredClaimNames.Sub, authRequest.username),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim(JwtRegisteredClaimNames.Iat, now.ToUniversalTime().ToString(), ClaimValueTypes.Integer64)

                    };


                    foreach (string role in user.roles)
                    {
                        claims.Add(new Claim("scope", role));
                    }

                    var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_settings.Value.Secret));

                    var jwt = new JwtSecurityToken(
                        issuer: _settings.Value.Iss,
                        audience: _settings.Value.Aud,
                        claims: claims,
                        notBefore: now,
                        expires: now.Add(TimeSpan.FromMinutes(Convert.ToDouble(_settings.Value.Times))),
                        signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
                    );
                    var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                    objAuthResponse.responsecode = "0";
                    objAuthResponse.expires = DateTime.Now.AddMinutes(60).ToString("ddd, dd MMM yyy HH':'mm':'ss 'GMT'");
                    objAuthResponse.issued = DateTime.Now.ToString("ddd, dd MMM yyy HH':'mm':'ss 'GMT'");
                    objAuthResponse.userName = user.Username;
                    
                    string credentials = $"{user.Username}:{AesEncryption.Encrypt(user.Password, key)}:{objAuthResponse.issued}";
                    objAuthResponse.refresh_token = AesEncryption.Encrypt(credentials, key);

                    objAuthResponse.expires_in = (int)TimeSpan.FromMinutes(Convert.ToDouble(60)).TotalMinutes;
                    objAuthResponse.token_type = "bearer";
                    objAuthResponse.access_token = encodedJwt;
                    objAuthResponse.responsecode = "200";
                    objAuthResponse.responsemsg = "success";

                    return Ok(objAuthResponse);
                }
                else
                {
                    objAuthResponse.access_token = "";
                    objAuthResponse.expires_in = 0;

                    return Unauthorized(objAuthResponse);
                }
            }
            catch (Exception est)
            {
                objAuthResponse.access_token = "";
                objAuthResponse.expires_in = 0;

                return NotFound(objAuthResponse);
            }

        }

        /*
        [HttpGet]
        public async Task<IActionResult> ChangeApiPassword(string username, string old_password, string new_password)
        {
            var authResponse = new ChangePassResponse();
            var changePassRequest = new ChangePassRequest();
            changePassRequest.username = username;
            changePassRequest.old_password = old_password;
            changePassRequest.new_password = new_password;

            try
            {
                #region api data receive
                old_password = BllEncryption.CreateMD5(old_password);
                new_password = BllEncryption.CreateMD5(new_password);
                User user = null;
                user = await _userService.AccessPermission(username, old_password);
                if (user != null)
                {
                    #region save data
                    var user1 = new User();
                    user1 = await _userService.UpdatePassword(username, old_password, new_password);
                    if (string.IsNullOrEmpty(user1.User_Id))
                    {
                        string strAuthKey = BllEncryption.funcGenerateToken(changePassRequest.username, changePassRequest.new_password);

                        authResponse.responsecode = "0";
                        authResponse.auth_key = strAuthKey;
                    }
                    else
                    {
                        authResponse.responsecode = ApiStatusCode.UserAuthFail; ;
                    }
                    #endregion
                }
                else
                {
                    authResponse.responsecode = ApiStatusCode.UserAuthFail; ;
                }

                #endregion
            }
            catch (Exception ess)
            {
                authResponse.responsecode = ApiStatusCode.InvalidParamater; ;
            }


            return Ok(authResponse);
        }
        */

    }
    
}
