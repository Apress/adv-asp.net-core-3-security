using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Data.Validation
{
    public class ImageFile : ValidationAttribute
    {
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            if (!(value is IFormFile))
                return new ValidationResult("This attribute can only be used on an IFormFile");

            byte[] fileBytes;

            var asFile = (IFormFile)value;

            using (var stream = asFile.OpenReadStream())
            {
                fileBytes = new byte[stream.Length];

                for (int i = 0; i < stream.Length; i++)
                {
                    fileBytes[i] = (byte)stream.ReadByte();
                }
            }

            var extension = System.IO.Path.GetExtension(asFile.FileName);

            switch (extension)
            {
                case ".jpg":
                case ".jpeg":
                    //If the first three bytes don't match the expected, fail the check
                    if (fileBytes[0] != 255 || fileBytes[1] != 216 || fileBytes[2] != 255)
                        return new ValidationResult("Image appears not to be in jpg format. Please try another.");
                    //If the fourth byte doesn't match one of the four expected values, fail the check
                    else if (fileBytes[3] != 219 && fileBytes[3] != 224 && fileBytes[3] != 238 && fileBytes[3] != 225)
                        return new ValidationResult("Image appears not to be in jpg format. Please try another.");
                    else
                        //All expected bytes match
                        return ValidationResult.Success;

                case ".gif":
                    //If bytes 1-4 and byte 6 aren't as expected, fail the check
                    if (fileBytes[0] != 71 || fileBytes[1] != 73 || fileBytes[2] != 70 || fileBytes[3] != 56 || fileBytes[5] != 97)
                        return new ValidationResult("Image appears not to be in gif format. Please try another.");
                    //If the fifth byte doesn't match one of the expected values, fail the check
                    else if (fileBytes[4] != 55 && fileBytes[4] != 57)
                        return new ValidationResult("Image appears not to be in gif format. Please try another.");
                    else
                        return ValidationResult.Success;
                case ".png":
                    if (fileBytes[0] != 137 || fileBytes[1] != 80 || fileBytes[2] != 78 || fileBytes[3] != 71 ||
                        fileBytes[4] != 13 || fileBytes[5] != 10 || fileBytes[6] != 26 || fileBytes[7] != 10)
                        return new ValidationResult("Image appears not to be in png format. Please try another.");
                    else
                        return ValidationResult.Success;
                default:
                    return new ValidationResult($"Extension {extension} is not supported. Please use gif, png, or jpg.");
            }

            //We shouldn't reach this line - log the error
            throw new InvalidOperationException("Last line reached in validating the ImageFile");
        }
    }
}
