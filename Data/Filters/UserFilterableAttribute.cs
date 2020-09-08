using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Data.Filters
{
    public class UserFilterableAttribute : Attribute
    {
        public string PropertyName { get; private set; }

        public UserFilterableAttribute(string propertyName)
        {
            PropertyName = propertyName;
        }

    }
}
