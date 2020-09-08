using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Headers
{
    public class CustomHeaderAttribute : ResultFilterAttribute
    {
        private const string _headerKey = "FromStartup";
        public override void OnResultExecuting(ResultExecutingContext context)
        {
            if (context.HttpContext.Response.Headers.ContainsKey(_headerKey))
                context.HttpContext.Response.Headers.Remove(_headerKey);

            context.HttpContext.Response.Headers.Add(_headerKey, "overridden");

            base.OnResultExecuting(context);
        }
    }
}
