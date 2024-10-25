using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;

public class Program
{
    public static void Main(string[] args)
    {
        // Generate initial key
        KeyManager.CreateKey();

        // Add an expired key for testing purposes
        var rsa = RSA.Create(2048);
        var expiredKey = new RsaSecurityKey(rsa);
        var expiredKid = Guid.NewGuid().ToString();
        expiredKey.KeyId = expiredKid;  // Set KeyId on the key itself
        var expiredDate = DateTime.UtcNow.AddMinutes(-10);
        KeyManager.keys[expiredKid] = (expiredKey, expiredDate);

        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
                webBuilder.UseUrls("http://localhost:8080"); // Serve HTTP on port 8080
            });
}

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseRouting();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });
    }
}

public class KeyManager
{
    public static Dictionary<string, (RsaSecurityKey key, DateTime expiry)> keys = new Dictionary<string, (RsaSecurityKey, DateTime)>();
    private static TimeSpan expiryPeriod = TimeSpan.FromHours(1);

    public static (RsaSecurityKey key, string kid) CreateKey()
    {
        var rsa = RSA.Create(2048);  // Create a new RSA key with 2048 bits
        var key = new RsaSecurityKey(rsa);
        var kid = Guid.NewGuid().ToString();  // Generate a unique kid (key ID)
        key.KeyId = kid;  // Set KeyId on the key itself
        var expiry = DateTime.UtcNow.Add(expiryPeriod);

        keys[kid] = (key, expiry);

        return (key, kid);
    }

    public static IEnumerable<(RsaSecurityKey key, string kid)> GetUnexpiredKeys()
    {
        var now = DateTime.UtcNow;
        return keys.Where(k => k.Value.expiry > now).Select(k => (k.Value.key, k.Key));
    }

    public static (RsaSecurityKey key, string kid)? GetKeyByExpiry(bool expired)
    {
        var now = DateTime.UtcNow;
        var key = expired
            ? keys.FirstOrDefault(k => k.Value.expiry < now)
            : keys.FirstOrDefault(k => k.Value.expiry > now);

        if (key.Equals(default(KeyValuePair<string, (RsaSecurityKey, DateTime)>)))
        {
            return null;
        }

        return (key.Value.key, key.Key);
    }

    public static string GetJWKS()
    {
        var unexpiredKeys = GetUnexpiredKeys();
        var jwks = new List<JsonWebKey>();

        foreach (var (key, kid) in unexpiredKeys)
        {
            var rsaParameters = key.Rsa?.ExportParameters(false) ?? key.Parameters;

            if (rsaParameters.Modulus == null || rsaParameters.Exponent == null)
            {
                throw new Exception("RSA key parameters are missing.");
            }

            jwks.Add(new JsonWebKey
            {
                Kid = kid,
                Kty = "RSA",
                Use = "sig",
                Alg = SecurityAlgorithms.RsaSha256,
                N = Base64UrlEncoder.Encode(rsaParameters.Modulus),
                E = Base64UrlEncoder.Encode(rsaParameters.Exponent)
            });
        }

        // Serialize the keys as a JWKS JSON object
        return JsonSerializer.Serialize(new { keys = jwks });
    }
}

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    [HttpPost]
    public IActionResult Authenticate([FromQuery] bool expired = false)
    {
        var keyData = KeyManager.GetKeyByExpiry(expired);
        if (keyData == null)
        {
            return BadRequest($"No {(expired ? "expired" : "unexpired")} keys available");
        }

        var (key, kid) = keyData.Value;
        var now = DateTime.UtcNow;

        // Set token expiry and notBefore depending on whether expired tokens are requested
        var expiry = expired ? now.AddMinutes(-30) : now.AddMinutes(30);
        var notBefore = expired ? now.AddMinutes(-60) : now;

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "user_id"),
                new Claim(JwtRegisteredClaimNames.Iat, ((DateTimeOffset)now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            }),
            Expires = expiry,
            NotBefore = notBefore,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
            Issuer = "selftest",
            Audience = "JustTest"
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        return Ok(new { token = tokenString });
    }
}

[ApiController]
[Route(".well-known/jwks.json")]
public class JWKSController : ControllerBase
{
    [HttpGet]
    public IActionResult GetJWKS()
    {
        var jwksJson = KeyManager.GetJWKS();
        return Ok(jwksJson);
    }
}
