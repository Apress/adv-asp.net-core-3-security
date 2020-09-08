using Advanced.Security.V3.Data.Validation;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Advanced.Security.V3.Models
{
    public class FileUploadModel
    {
        [Display(Name = "File Name")]
        [Required]
        public string FileName { get; set; }

        [Display(Name = "Test File")]
        [ImageFile]
        [Required]
        public IFormFile FormFile { get; set; }
    }
}
