using Advanced.Security.V3.Data.Validation;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Models
{
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
}
