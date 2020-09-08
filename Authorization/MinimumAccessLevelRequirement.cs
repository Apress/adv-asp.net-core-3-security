using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Authorization
{
    public class MinimumAccessLevelRequirement : IAuthorizationRequirement
    {
        private int _minimumValue;
        private List<Role> _allowedRoles;

        public MinimumAccessLevelRequirement(string role)
        {
            _allowedRoles = new List<Role>();

            _allowedRoles.Add(new Role() { Text = "Administrator", SortValue = 10 });
            _allowedRoles.Add(new Role() { Text = "Manager", SortValue = 5 });
            _allowedRoles.Add(new Role() { Text = "Individual", SortValue = 2 });

            //TODO: Add better error handling here
            _minimumValue = _allowedRoles.Single(r => r.Text == role).SortValue;
        }

        public bool RoleIsMatch(string role)
        {
            var value = _allowedRoles.Single(r => r.Text == role).SortValue;
            return value >= _minimumValue;
        }

        private struct Role
        {
            public int SortValue;
            public string Text;
        }
    }
}
