using jWtTokenWebApi.Interfaces;
using jWtTokenWebApi.Models;
using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace jWtTokenWebApi.Services
{
    public class UserService : IUserService
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public UserService(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

       
        public async Task<User> AccessPermission(string username, string password)
        {
            var user = new User();
            if (username != "" && password != "")
            {
                int validStat = 0;
                user.Username = username;
                user.Password = password;
                /*  this code use for  user verification so you change as your requirement, also you can use database
                 * var client = _httpClientFactory.CreateClient("SpgClient");
                var responseMessage = await client.PostAsJsonAsync($"api/security/VerifyUserAuthentication", user);
                var responseString = await responseMessage.Content.ReadAsStringAsync();
                //dynamic json = JsonSerializer.Deserialize<object>(responseString);
                // Unescape the string to get the actual JSON
                string unescapedJson = System.Text.RegularExpressions.Regex.Unescape(responseString);

                // Remove the leading and trailing double quotes from the unescaped string
                unescapedJson = unescapedJson.Trim('"');

                // Deserialize the response to StatusResponse object
                var strats = JsonSerializer.Deserialize<StatusResponse>(unescapedJson);

                if (strats.status)
                {               
                    user.roles.Add("SPG");
                }
                else
                {
                    user=new User();
                }*/

                return user;
            }
            else
                return user;
        }

        /*
        Task<User> IUserService.UpdatePassword(string username, string password, string newpassword)
        {
            var user = new User();
            if (username != "" && password != "")
            {
                var dbUser = _context.Tbl_Users.Where(s => s.UserId == username && s.Password == password && s.Status == 1).FirstOrDefault();
                if (dbUser != null)
                {
                    dbUser.UserId = username;
                    dbUser.Password = newpassword;
                    user.User_Id = username;
                    user.UserName = username;
                    _context.SaveChanges();
                    return Task.FromResult(user);
                }
                else
                    return Task.FromResult<User>(null);
            }
            else
                return Task.FromResult<User>(null);
        }*/

    }
}
