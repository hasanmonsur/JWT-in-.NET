using jWtTokenWebApi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace jWtTokenWebApi.Interfaces
{
    public interface IUserService
    {
        Task<User> AccessPermission(string username, string password);
        //Task<User> UpdatePassword(string username, string password, string newpassword);
    }
}
