using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace jWtTokenWebApi.Models
{
    public class AuthRequest
    {
        public string grant_type { get; set; }
        public string username { get; set; }
        public string Password { get; set; }
    }

    public class AuthRefreshRequest
    {
        public string refresh_token { get; set; }
    }

    public class AuthResponse
    {
        public string access_token { get; set; }
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public string refresh_token { get; set; }
        //public string scope { get; set; }
        //public string client_id { get; set; }
        public string userName { get; set; }
        public string issued { get; set; }
        public string expires { get; set; }
        public string responsecode { get; set; }
        public string responsemsg { get; set; }
        //public string x_api_key { get; set; }
    }

    public class ChangePassRequest
    {
        public string username { get; set; }
        public string old_password { get; set; }
        public string new_password { get; set; }
    }

    public class AuthChangePassRequest
    {
        public string userName { get; set; }
        public string oldPassword { get; set; }
        public string newPassword { get; set; }
    }

    public class ChangePassResponse
    {
        public string auth_key { get; set; }
        public string responsecode { get; set; }
    }


    public class User
    {
        public User()
        {
            roles = new List<string>();
        }
        public string Username { get; set; }
        public string Password { get; set; }
        public List<string> roles { get; set; }
    }
    
}
