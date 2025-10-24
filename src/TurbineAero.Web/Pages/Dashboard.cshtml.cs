using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace TurbineAero.Web.Pages;

[Authorize]
public class DashboardModel : PageModel
{
    public void OnGet()
    {
    }
}
