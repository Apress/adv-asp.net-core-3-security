using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Data.Validation
{
    public class IsValidAge : System.ComponentModel.DataAnnotations.ValidationAttribute
    {
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            int age;

            if (value == null || !int.TryParse(value.ToString(), out age))
                return new ValidationResult("Age must be a number");

            if (age < 18 || age > 120)
                return new ValidationResult("Age must be greater or equal to 18 and less than 120");

            return ValidationResult.Success;
        }
    }
}
