using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using AuthenticationProvider.Core.AuthenticationService;
using AuthenticationProvider.Core.Filters;
using AuthenticationProvider.Core.Model;
using Microsoft.AspNetCore.Mvc;
using WebMVC.Models;

namespace WebMVC.Controllers
{
   
    public class HomeController : Controller
    {
        public HomeController()
        {
          
        }

      
        public IActionResult Index()
        {
            return View();
        }
        [ClaimAuthorization("ADMIN")]
        public IActionResult Privacy()
        {
            return View();
        }

        [ClaimAuthorization("READER")]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
