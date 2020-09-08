using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Data.Filters
{
    /// <summary>
    /// This exception should be used when a query returns results without a user filter but returns no results with one
    /// </summary>
    public class ItemNotInUserContextException : ApplicationException
    {
    }
}
