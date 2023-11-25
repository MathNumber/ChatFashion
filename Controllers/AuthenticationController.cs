using FormulaOneApp.Data;
using FormulaOneApp.Models;
using FormulaOneApp.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RestSharp;
using RestSharp.Authenticators;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace FormulaOneApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly AppDbContext _context;
        private readonly TokenValidationParameters _tokenValidationParameters;
        //private readonly JwtConfig _jwtConfig;

        public AuthenticationController
            (
                UserManager<IdentityUser> userManager,
                IConfiguration configuration,
                AppDbContext context,
                TokenValidationParameters tokenValidationParameters
                //JwtConfig jwtConfig
            )
        {
            //_jwtConfig = jwtConfig;
            _userManager = userManager;
            _configuration = configuration;
            _context = context;
            _tokenValidationParameters = tokenValidationParameters;
        }

        [HttpPost]
        [Route("Registor")]
        public async Task<IActionResult> Registor([FromBody] UserRegistrationRequestDto requestDto)
        {
            if (ModelState.IsValid)
            {
                var user_exitst = await _userManager.FindByEmailAsync(requestDto.Email);
                if (user_exitst != null)
                {
                    return BadRequest(new AuthResult
                    {
                        Result = false,
                        Errors = new List<string>()
                {
                    "Email already exitst"
                }
                    });
                }
                var new_user = new IdentityUser()
                {
                    Email = requestDto.Email,
                    UserName = requestDto.Email,
                    EmailConfirmed = false
                };
                var is_created = await _userManager.CreateAsync(new_user, requestDto.Password);

                if (is_created.Succeeded)
                {
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(new_user);

                    var email_body = $"<p>Please confirm your email <a href='#URL#'><button>Click here</button></a>.</p>";

                    var callback_url = Request.Scheme + "://" + Request.Host + Url.Action("ConfirmEmail", "Authentication", new { userId = new_user.Id, code = code });

                    var body = email_body.Replace("#URL#", callback_url);

                    var result = SendEmail(body, new_user.Email);

                    if (result)
                    {
                        return Ok("Please verify your email, through the verification email we have just sent.");
                    }
                    else
                    {
                        await _userManager.DeleteAsync(new_user);
                        return Ok("Please request an email verification link");
                    }
                }

                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
            {
                "Server error"
            },
                    Result = false
                });
            }
            return BadRequest();
        }


        [Route("ConfirmEmail")]
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId,string code)
        {
            if (userId == null || code == null)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid email confirmation url"
                    }
                });
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid email parameter"
                    }
                });
            }
            //code = Encoding.UTF8.GetString(Convert.FromBase64String(code));
            var result = await _userManager.ConfirmEmailAsync(user, code);
            var status = result.Succeeded ? "Thank you for confirming your email" : "Your email is not confirmed, please try again later";
            return Ok(status);
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDto loginRequest)
        {
            if (ModelState.IsValid)
            {
                var existing_user = await _userManager.FindByEmailAsync(loginRequest.Email);

                if (existing_user == null)
                    return BadRequest(new AuthResult()
                    {
                        Errors = new List<string>()
                {
                    "Invalid payload"
                },
                        Result = false
                    });

                if (!existing_user.EmailConfirmed)
                    return BadRequest(new AuthResult()
                    {
                        Errors = new List<string>()
                {
                    "Email needs to be confirmed"
                },
                        Result = false
                    });

                var isCorrect = await _userManager.CheckPasswordAsync(existing_user, loginRequest.Password);

                if (!isCorrect)
                    return BadRequest(new AuthResult()
                    {
                        Errors = new List<string>()
                {
                    "Invalid credentials"
                },
                        Result = false
                    });

                var jwtToken = await GenerateJwtToken(existing_user);
                var userId = existing_user.Id;
                var email = existing_user.Email;
                return Ok(new { UserId = userId, Token = jwtToken, Email = email });
            }
            return BadRequest(new AuthResult()
            {
                Errors = new List<string>()
        {
            "Invalid payload"
        },
                Result = false
            });
        }


        [HttpPatch]
        [Route("ChangeEmail")]
        public async Task<IActionResult> ChangeEmail(string userId, string newEmail)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(newEmail))
            {
                return BadRequest("Invalid request.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest("User not found.");
            }

            var result = await _userManager.SetEmailAsync(user, newEmail);
            if (!result.Succeeded)
            {
                return BadRequest("Error while changing email.");
            }

            var code = await _userManager.GenerateChangeEmailTokenAsync(user, newEmail);
            var callbackUrl = Url.Action("ConfirmNewEmail", "Authentication", new { userId = user.Id, email = newEmail, code = code }, protocol: HttpContext.Request.Scheme);
            var emailBody = $"Please confirm your new email by clicking here: {callbackUrl}";
            var emailSent = SendEmail(emailBody, newEmail);
            if (!emailSent)
            {
                return BadRequest("Failed to send confirmation email.");
            }

            return Ok("Email change request successful. Please check your new email to confirm.");
        }


        [HttpGet]
        [Route("ConfirmNewEmail")]
        public async Task<IActionResult> ConfirmNewEmail(string userId, string email, string code)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null || code == null)
            {
                return BadRequest("Invalid request.");
            }

            var result = await _userManager.ChangeEmailAsync(user, email, code);
            if (!result.Succeeded)
            {
                return BadRequest("Error confirming email.");
            }

            return Ok("Email confirmed successfully.");
        }

        [HttpPatch]
        [Route("ChangePassword")]
        public async Task<IActionResult> ChangePassword(string userId, string newPass)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(newPass))
            {
                return BadRequest("Invalid request.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest("User not found.");
            }

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, resetToken, newPass);
            if (!result.Succeeded)
            {
                return BadRequest("Error while changing password.");
            }

            return Ok("Password changed successfully.");
        }




        [HttpDelete]
        [Route("DeleteAccount")]
        public async Task<IActionResult> DeleteAccount(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("Invalid request.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest("User not found.");
            }

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest("Error while deleting account.");
            }

            return Ok("Account deleted successfully.");
        }


        private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim("Id", user.Id),
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Email, value:user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
        }),
                Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value)) ,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                Token= RandomStringGeneration(23),
                AddedDate=DateTime.UtcNow,
                ExpiryDate=DateTime.UtcNow.AddMonths(6),
                IsRevoked=false,
                IsUsed=false,
                UserId=user.Id
            };

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            return new AuthResult()
            {
                Token = jwtToken,
                RefreshToken = refreshToken.Token,
                Result = true
            };
        }

        [HttpPost]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if (ModelState.IsValid)
            {
                var result = await VerifyAndGenerateToken(tokenRequest);

                if (result==null)
                    return BadRequest(new AuthResult()
                    {
                        Errors = new List<string>()
                    {
                        "Invalid tokens"
                    },
                        Result = false
                    });
                return Ok(result);

            }
            return BadRequest(new AuthResult()
            {
                Errors = new List<string>()
                {
                    "Invalid parameters"
                },
                Result = false
            });
        }

        private async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                _tokenValidationParameters.ValidateLifetime = false;
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);
                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase);
                    if (result == false)
                        return null;
                }
                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x=>x.Type==JwtRegisteredClaimNames.Exp).Value);

                var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                if (expiryDate > DateTime.Now)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Expired Token"
                        }
                    };
                }
                var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

                if (storedToken == null)
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid tokens"
                        }
                    };
                if (storedToken.IsUsed)
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid tokens"
                        }
                    };
                if (storedToken.IsRevoked)
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid tokens"
                        }
                    };
                var jti = tokenInVerification.Claims.FirstOrDefault(x=>x.Type==JwtRegisteredClaimNames.Jti).Value;

                if (storedToken.JwtId != jti)
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid tokens"
                        }
                    };
                if(storedToken.ExpiryDate<DateTime.UtcNow)
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Expired tokens"
                        }
                    };
                storedToken.IsUsed = true;
                _context.RefreshTokens.Update(storedToken);
                await _context.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);

                return await GenerateJwtToken(dbUser);

            }
            catch (Exception e)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                        {
                            "Server error"
                        }
                };
            }
        }

        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970,1,1,0,0,0,0,DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();
            return dateTimeVal;
        }

        private bool SendEmail(string body, string email)
        {
            var client = new RestClient("https://api.mailgun.net/v3");
            var request = new RestRequest("", Method.Post);
            client.Authenticator =
                new HttpBasicAuthenticator("api", _configuration.GetSection("EmailConfig:API_KEY").Value);
            request.AddParameter("domain", "sandboxbc1d9bde378043a3afeed77e94fd3de8.mailgun.org", ParameterType.UrlSegment);
            request.Resource = "{domain}/messages";
            request.AddParameter("from", "ChatFashion <postmaster@sandboxbc1d9bde378043a3afeed77e94fd3de8.mailgun.org>");
            request.AddParameter("to", "xepaso5479@dpsols.com");
            request.AddParameter("subject", "Email Verification");

            request.AddParameter("html", body);
            request.Method = Method.Post;
            var response = client.Execute(request);
            return response.IsSuccessful;
        }


        private string RandomStringGeneration(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz_";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
