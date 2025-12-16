using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Bookstore.Api.Exceptions;
using Bookstore.Api.Middleware;
using Bookstore.Api.Models;
using Bookstore.Api.Security;
using Bookstore.Api.Services;
using FirebaseAdmin.Auth;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using Microsoft.AspNetCore.Authorization;

namespace Bookstore.Api.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly UserService _userService;
        private readonly JwtService _jwtService;

        public AuthController(
            UserService userService,
            JwtService jwtService,
            IConfiguration configuration
        )
        {
            _userService = userService;
            _jwtService = jwtService;
            _configuration = configuration;
        }

        [HttpPost("login")]
        [SwaggerOperation(
            Summary = "User login",
            Description = "Verifies credentials and returns a signed JWT on success."
        )]
        public virtual async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            if (!ModelState.IsValid)
                throw new BadRequestException("Invalid credentials format.");

            var user = await _userService.GetByEmailAsync(dto.Email);
            if (user == null)
                throw new UnauthorizedException("Invalid credentials.");

            var isValidPassword = PasswordHasher.Verify(dto.Password, user.Password);
            if (!isValidPassword)
                throw new UnauthorizedException("Invalid credentials.");

            var token = _jwtService.GenerateToken(user);
            var refreshToken = _jwtService.GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7); // Set expiry
            await _userService.UpdateAsync(user.UserId, user);
            if (user.UserId == null)
                return Unauthorized();
            return Ok(
                new
                {
                    token,
                    refreshToken,
                    expiresIn = _jwtService.ExpirationMinutes,
                    user = new
                    {
                        user.UserId,
                        user.Email,
                        user.Name,
                        user.IsAdmin,
                    },
                }
            );
        }

        [HttpPost("logout")]
        [SwaggerOperation(
            Summary = "Logout user",
            Description = "Clears the authentication token on client side. Since JWT is stateless, the backend simply returns a success response."
        )]
        public IActionResult Logout()
        {
            return Ok(new { message = "User logged out successfully." });
        }

        // refresh token
        [HttpPost("refresh")]
        [SwaggerOperation(
            Summary = "Refresh JWT token",
            Description = "Provides a new access token using a valid refresh token."
        )]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenDto dto)
        {
            var principal = _jwtService.GetPrincipalFromExpiredToken(dto.AccessToken);
            var email = principal.FindFirstValue(ClaimTypes.Email);

            var user = await _userService.GetByEmailAsync(email!);
            if (
                user == null
                || user.RefreshToken != dto.RefreshToken
                || user.RefreshTokenExpiry <= DateTime.UtcNow
            )
                throw new UnauthorizedException("Invalid or expired refresh token.");

            var newAccessToken = _jwtService.GenerateToken(user);
            var newRefreshToken = _jwtService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userService.UpdateAsync(user.UserId, user);

            return Ok(
                new
                {
                    accessToken = newAccessToken,
                    refreshToken = newRefreshToken,
                    expiresIn = _jwtService.ExpirationMinutes,
                }
            );
        }

        //==================================================================
        // Firebase Authentication
        //==================================================================
        [HttpPost("firebase")]
        [AllowAnonymous]
        [SwaggerOperation(
            Summary = "Firebase login",
            Description = "Authenticates a user using a Firebase ID token and returns a signed JWT."
        )]
        public async Task<IActionResult> FirebaseLogin([FromBody] FirebaseLoginDto dto)
        {
            FirebaseToken decodedToken;

            try
            {
                decodedToken = await FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(dto.IdToken);
            }
            catch
            {
                throw new UnauthorizedException("Invalid or expired Firebase token.");
            }

            if (!decodedToken.Claims.TryGetValue("email", out var emailObj))
                throw new UnauthorizedException("Firebase token does not contain email.");

            var email = emailObj.ToString();
            var uid = decodedToken.Uid;

            var name = decodedToken.Claims.TryGetValue("name", out var nameObj)
                ? nameObj?.ToString()
                : "Firebase User";

            var user = await _userService.GetByEmailAsync(email!);

            if (user == null)
            {
                user = new User
                {
                    Email = email!,
                    Name = name!,
                    AuthProvider = "Firebase",
                    ProviderUserId = uid,
                    IsAdmin = false,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                };

                await _userService.CreateAsync(user);
            }

            var token = _jwtService.GenerateToken(user);
            var refreshToken = _jwtService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
            user.UpdatedAt = DateTime.UtcNow;

            await _userService.UpdateAsync(user.UserId, user);

            return Ok(
                new
                {
                    token,
                    refreshToken,
                    expiresIn = _jwtService.ExpirationMinutes,
                }
            );
        }

        //==================================================================
        // GOogle Authentication
        //==================================================================
        [HttpPost("google")]
        [AllowAnonymous]
        [SwaggerOperation(
            Summary = "Google login",
            Description = "Authenticates a user using a Google ID token and returns a JWT."
        )]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginDto dto)
        {
            GoogleJsonWebSignature.Payload payload;

            try
            {
                payload = await GoogleJsonWebSignature.ValidateAsync(
                    dto.IdToken,
                    new GoogleJsonWebSignature.ValidationSettings
                    {
                        Audience = new[] { _configuration["GOOGLE_CLIENT_ID"] },
                    }
                );
            }
            catch
            {
                throw new UnauthorizedException("Invalid Google ID token.");
            }

            // Extract identity from Google token
            var email = payload.Email;
            var name = payload.Name;
            var googleUserId = payload.Subject;

            if (string.IsNullOrEmpty(email))
                throw new UnauthorizedException("Google token does not contain email.");

            // Find or create user
            var user = await _userService.GetByEmailAsync(email);

            if (user == null)
            {
                user = new User
                {
                    Email = email,
                    Name = name,
                    AuthProvider = "Google",
                    ProviderUserId = googleUserId,
                    IsAdmin = false,
                };

                await _userService.CreateAsync(user);
            }

            // Issue your own JWT
            var token = _jwtService.GenerateToken(user);
            var refreshToken = _jwtService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
            await _userService.UpdateAsync(user.UserId, user);

            return Ok(
                new
                {
                    token,
                    refreshToken,
                    expiresIn = _jwtService.ExpirationMinutes,
                    user = new
                    {
                        user.UserId,
                        user.Email,
                        user.Name,
                        user.IsAdmin,
                    },
                }
            );
        }

        [HttpGet("test/login-url")]
        [AllowAnonymous]
        public IActionResult GetGoogleAuthUrl()
        {
            var clientId = _configuration["GOOGLE_CLIENT_ID"];
            var redirectUri = "http://localhost:5149/api/auth/test/callback";

            if (string.IsNullOrEmpty(clientId))
            {
                return BadRequest("GOOGLE_CLIENT_ID est introuvable dans la configuration.");
            }
            var url =
                $"https://accounts.google.com/o/oauth2/v2/auth?"
                + $"client_id={clientId}&"
                + $"response_type=code&"
                + $"scope=openid%20email%20profile&"
                + $"redirect_uri={redirectUri}";

            return Redirect(url);
        }

        [HttpGet("test/callback")]
        [AllowAnonymous]
        public async Task<IActionResult> GoogleCallback([FromQuery] string code)
        {
            var clientId = _configuration["GOOGLE_CLIENT_ID"];
            var clientSecret = _configuration["GOOGLE_CLIENT_ID_SECRET"];
            var redirectUri = "http://localhost:5149/api/auth/test/callback";

            if (string.IsNullOrEmpty(code))
                return BadRequest("Code manquant.");
            using var httpClient = new HttpClient();

            var tokenRequest = new HttpRequestMessage(
                HttpMethod.Post,
                "https://oauth2.googleapis.com/token"
            );

            var paramsDict = new Dictionary<string, string>
            {
                { "code", code },
                { "client_id", clientId! },
                { "client_secret", clientSecret! },
                { "redirect_uri", redirectUri },
                { "grant_type", "authorization_code" },
            };

            tokenRequest.Content = new FormUrlEncodedContent(paramsDict);

            var response = await httpClient.SendAsync(tokenRequest);
            var responseString = await response.Content.ReadAsStringAsync();
            return Content(responseString, "application/json");
        }
    }

    // DTOs
    public record RegisterDto(
        string Email,
        string Password,
        string Name,
        DateTime? BirthDate,
        Gender? Gender,
        string? Address,
        string? PhoneNumber,
        string? ProfileImage
    );

    public record FirebaseLoginDto(string IdToken);

    public record GoogleLoginDto(string IdToken);

    public record LoginDto(string Email, string Password);

    public record RefreshTokenDto(string AccessToken, string RefreshToken);
}
