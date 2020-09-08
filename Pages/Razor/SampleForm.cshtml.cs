using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Advanced.Security.V3.Data.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Advanced.Security.V3.Razor
{
    [AllowAnonymous]
    public class SampleFormModel : PageModel
    {
        [BindProperty]
        public SampleModel Model { get; set; }

        public class SampleModel
        {
            [StringLength(100)]
            [Required]
            [Display(Name = "Name")]
            public string Name { get; set; }

            [StringLength(100)]
            [Required]
            [EmailAddress]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [StringLength(20)]
            [Required]
            [RegularExpression("^(a|A)(.*)")]
            [Display(Name = "Word that starts with \"A\"")]
            public string Word { get; set; }

            [Display(Name = "Age")]
            [IsValidAge]
            public int Age { get; set; }

            [Display(Name = "Number Of Pets")]
            public ushort PetCount { get; set; }
        }

        public void OnGet()
        {
            ViewData["Message"] = "Submit the form to test";
        }

        public void OnPost()
        {
            if (ModelState.IsValid)
                ViewData["Message"] = "Data is valid!";
            else
                ViewData["Message"] = "Please correct these errors and try again:";
        }
    }
}