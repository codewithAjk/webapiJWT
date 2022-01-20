using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WebApiJwt.Models
{
    public class ChangePasswordModel
    {
        [Required(ErrorMessage = "Username is required")]
        public string Username { get; set; }

        [Required(ErrorMessage = "CurrentPassword is required")]
        public string CurrentPassword { get; set; }

        [Required(ErrorMessage = "NewPassword is required")]
        public string NewPassword { get; set; }

        [Required(ErrorMessage = "ConfirmNewPassword is required")]
        public string ConfirmNewPassword { get; set; }

    }
}
