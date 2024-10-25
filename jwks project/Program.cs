using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public class Program
{
    public static void Main(string[] args)
    {
        KeyManager.InitializeDatabase();
        KeyManager.CreateAndStoreKey(expired: true); // Create an expired key for testing
        KeyManager.CreateAndStoreKey(expired: false); // Create a valid key for testing

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

public static class KeyManager
{
    private static readonly string ConnectionString = "Data Source=totally_not_my_privateKeys.db;";

    public static void InitializeDatabase()
    {
        using var connection = new SQLiteConnection(ConnectionString);
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = @"CREATE TABLE IF NOT EXISTS keys(
                                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                                    key BLOB NOT NULL,
                                    exp INTEGER NOT NULL)";
        command.ExecuteNonQuery();
    }

    public static void CreateAndStoreKey(bool expired)
    {
        using var rsa = RSA.Create(2048);
        var expiry = DateTimeOffset.UtcNow.AddHours(expired ? -1 : 1).ToUnixTimeSeconds();
        var pemKey = ExportKeyToPEM(rsa);

        using var connection = new SQLiteConnection(ConnectionString);
        connection.Open();
        var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO keys (key, exp) VALUES (?, ?)";

        // Explicitly adding parameters using `?` placeholders
        command.Parameters.Add(new SQLiteParameter { Value = Encoding.UTF8.GetBytes(pemKey) });
        command.Parameters.Add(new SQLiteParameter { Value = expiry });

        command.ExecuteNonQuery();
    }

    public static (RsaSecurityKey key, int kid)? GetKey(bool expired)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var query = expired
            ? "SELECT kid, key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1"
            : "SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1";

        using var connection = new SQLiteConnection(ConnectionString);
        connection.Open();
        var command = connection.CreateCommand();
        command.CommandText = query;

        // Adding the parameter with positional placeholder `?`
        command.Parameters.Add(new SQLiteParameter { Value = now });

        using var reader = command.ExecuteReader();
        if (reader.Read())
        {
            var kid = reader.GetInt32(0);
            var pemKey = Encoding.UTF8.GetString((byte[])reader["key"]);
            var rsa = ImportKeyFromPEM(pemKey);
            var rsaSecurityKey = new RsaSecurityKey(rsa) { KeyId = kid.ToString() };

            return (rsaSecurityKey, kid);
        }

        return null;
    }

    public static IEnumerable<(RsaSecurityKey key, int kid)> GetUnexpiredKeys()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var connection = new SQLiteConnection(ConnectionString);
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = "SELECT kid, key FROM keys WHERE exp > ?";

        // Adding the parameter with positional placeholder `?`
        command.Parameters.Add(new SQLiteParameter { Value = now });

        using var reader = command.ExecuteReader();
        var keys = new List<(RsaSecurityKey, int)>();

        while (reader.Read())
        {
            var kid = reader.GetInt32(0);
            var pemKey = Encoding.UTF8.GetString((byte[])reader["key"]);
            var rsa = ImportKeyFromPEM(pemKey);
            keys.Add((new RsaSecurityKey(rsa) { KeyId = kid.ToString() }, kid));
        }

        return keys;
    }

    private static string ExportKeyToPEM(RSA rsa)
    {
        var key = rsa.ExportRSAPrivateKey();
        return Convert.ToBase64String(key);
    }

    private static RSA ImportKeyFromPEM(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(pem), out _);
        return rsa;
    }

    public static string GetJWKS()
    {
        var unexpiredKeys = GetUnexpiredKeys();
        var jwks = unexpiredKeys.Select(k => new JsonWebKey
        {
            Kid = k.kid.ToString(),
            Kty = "RSA",
            Use = "sig",
            Alg = SecurityAlgorithms.RsaSha256,
            N = Base64UrlEncoder.Encode(k.key.Rsa.ExportParameters(false).Modulus),
            E = Base64UrlEncoder.Encode(k.key.Rsa.ExportParameters(false).Exponent)
        });

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
        var keyData = KeyManager.GetKey(expired);
        if (keyData == null)
        {
            return BadRequest($"No {(expired ? "expired" : "unexpired")} keys available");
        }

        var (key, kid) = keyData.Value;
        var now = DateTime.UtcNow;

        var expiry = expired ? now.AddMinutes(-30) : now.AddMinutes(30);
        var notBefore = expired ? now.AddMinutes(-60) : now;

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
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
