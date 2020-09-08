using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Advanced.Security.V3.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Advanced.Security.V3.Logging;
using Advanced.Security.V3.Headers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Advanced.Security.V3.Data.Primary;
using Microsoft.EntityFrameworkCore;
using Advanced.Security.V3.ResourceFilters;
using Advanced.Security.V3.Data.Filters;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Identity;

namespace Advanced.Security.V3.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly ISecurityLogger _securityLogger;
        private readonly IWebHostEnvironment _environment;

        public HomeController(ILogger<HomeController> logger, RoleManager<IdentityRole> roleManager, ApplicationDbContext dbContext, ISecurityLogger securityLogger,
            IWebHostEnvironment environment)
        {
            _logger = logger;
            _roleManager = roleManager;
            _dbContext = dbContext;
            _securityLogger = securityLogger;
            _environment = environment;
        }

        [AllowAnonymous]
        public IActionResult Index()
        {
            ViewBag.Environment = _environment.EnvironmentName;
            return View();
        }

        [AllowAnonymous]
        public IActionResult Auth()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult Forms()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult Sql()
        {
            return View();
        }

        [CustomHeader]
        public IActionResult Privacy()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult ThrowError()
        {
            //No view exists, so throw an error
            return View();
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            var context = HttpContext.Features.Get<IExceptionHandlerFeature>();

            var requestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;

            _securityLogger.LogEvent(LogLevel.Error, SecurityEvent.General.EXCEPTION, $"An error occurred, request ID: {requestId}", context.Error);

            return View(new ErrorViewModel { RequestId = requestId });
        }

        [Route("/Error")]
        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult CustomErrorPage()
        {
            var context = HttpContext.Features.Get<IExceptionHandlerFeature>();

            var requestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;

            _securityLogger.LogEvent(LogLevel.Error, SecurityEvent.General.EXCEPTION, $"An error occurred, request ID: {requestId}", context.Error);

            return View(new ErrorViewModel { RequestId = requestId });
        }

        [Authorize(Roles = "Administrator")]
        public IActionResult Administrator()
        {
            return View();
        }

        [Authorize(Roles = "Author")]
        public IActionResult Author()
        {
            return View();
        }

        [Authorize(Policy = "RequireAuthorship")]
        public IActionResult RequireAuthorship()
        {
            return View();
        }

        [Authorize(Policy = "MinimumAccessLevelManager")]
        public IActionResult MinimumAccessLevelManager()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult RawConcat(string query)
        {
            if (string.IsNullOrEmpty(query))
                query = "honey";

            ViewBag.Count = _dbContext.Food.FromSqlRaw("SELECT * FROM Food WHERE FoodName = '" + query + "'").Count();
            return View("Query");
        }

        [AllowAnonymous]
        public IActionResult RawInterpolated(string query)
        {
            if (string.IsNullOrEmpty(query))
                query = "honey";

            ViewBag.Count = _dbContext.Food.FromSqlRaw($"SELECT * FROM Food WHERE FoodName = '{query}'").Count();
            return View("Query");
        }

        //[AllowAnonymous]
        //public IActionResult PreFormatInterpolated(string query)
        //{
        //    if (string.IsNullOrEmpty(query))
        //        query = "honey";

        //    var fullQuery = $"SELECT * FROM Food WHERE FoodName = '{query}'";
        //    ViewBag.Count = _dbContext.Food.FromSqlInterpolated(fullQuery).Count();
        //    return View("Query");
        //}

        //[AllowAnonymous]
        //public IActionResult ConcatInterpolated(string query)
        //{
        //    if (string.IsNullOrEmpty(query))
        //        query = "honey";

        //    ViewBag.Count = _dbContext.Food.FromSqlInterpolated("SELECT * FROM Food WHERE FoodName = '" + query + "'").Count();
        //    return View("Query");
        //}

        [AllowAnonymous]
        public IActionResult FullInterpolated(string query)
        {
            if (string.IsNullOrEmpty(query))
                query = "honey";

            ViewBag.Count = _dbContext.Food.FromSqlInterpolated($"SELECT * FROM Food WHERE FoodName = '{query}'").Count();
            return View("Query");
        }

        [AllowAnonymous]
        public IActionResult RawWithParam(string query)
        {
            if (string.IsNullOrEmpty(query))
                query = "honey";

            ViewBag.Count = _dbContext.Food.FromSqlRaw("SELECT * FROM Food WHERE FoodName = {0}", query).Count();
            return View("Query");
        }

        [HttpGet]
        [Honeypot]
        [AllowAnonymous]
        [Route("/wp-login.php")]
        public IActionResult FalseLogin()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ViewOrder(int orderId)
        {
            if (orderId == 0)
                ViewBag.OrderInfo = "Order ID Invalid";

            var order = _dbContext.Order.SingleOrDefaultInUserContext(HttpContext, o => o.OrderId == orderId);

            if (order == null)
            {
                ViewBag.OrderInfo = "Order Not Found";
                _securityLogger.LogEvent(LogLevel.Information, new SecurityEventType(5000, SecurityEventType.SecurityLevel.SECURITY_WARNING), $"Order ID: {orderId} was not found");
            }
            else
            {
                ViewBag.OrderInfo = "Ordered On: " + order.OrderDate.ToString();
            }

            return View();
        }

        [HttpPost]
        [Honeypot]
        [AllowAnonymous]
        [Route("/wp-login.php")]
        public IActionResult FalseLogin(int ignoreMe)
        {
            ViewData["Error"] = "An error occurred.";
            return View();
        }
    }
}
