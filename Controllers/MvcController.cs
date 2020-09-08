using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Advanced.Security.V3.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Advanced.Security.V3.Controllers
{
    [Authorize]
    public class MvcController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public IActionResult SharedForm()
        {
            ViewData["Message"] = "Submit the form to test";
            return View();
        }

        [HttpPost]
        public IActionResult SharedForm(SampleModel model)
        {
            if (ModelState.IsValid)
                ViewData["Message"] = "Data is valid!";
            else
                ViewData["Message"] = "Please correct these errors and try again:";

            return View();
        }

        [HttpGet]
        public IActionResult SampleForm()
        {
            ViewData["Message"] = "Submit the form to test";
            return View();
        }

        [HttpPost]
        public IActionResult SampleForm(SampleModel model)
        {
            if (ModelState.IsValid)
                ViewData["Message"] = "Data is valid!";
            else
                ViewData["Message"] = "Please correct these errors and try again:";

            return View();
        }

        [HttpGet]
        public IActionResult FileUpload()
        {
            ViewData["Message"] = "Submit the form to test";
            return View();
        }

        [HttpPost]
        public IActionResult FileUpload(FileUploadModel model)
        {
            if (ModelState.IsValid)
                ViewData["Message"] = "Data is valid!";
            else
                ViewData["Message"] = "Please correct these errors and try again:";

            return View();
        }
    }
}
