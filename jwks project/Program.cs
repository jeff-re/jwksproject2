using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Konscious.Security.Cryptography;
using System;
using System.Collections.Concurrent;
using System.Data.SQLite;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

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
                webBuilder.UseUrls("http://localhost:8080");
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

public static class DatabaseHelper
{
    public static void ExecuteWithRetry(Action action, int maxRetries = 5, int delayMs = 100)
    {
        int attempt = 0;
        while (attempt < maxRetries)
        {
            try
            {
                action();
                return; // If successful, exit the method
            }
            catch (SQLiteException ex) when (ex.Message.Contains("database is locked"))
            {
                attempt++;
                if (attempt == maxRetries)
                {
                    throw; // Rethrow the exception after exhausting retries
                }
                Thread.Sleep(delayMs); // Wait before retrying
            }
        }
    }
}

public static class KeyManager
{
    private static readonly string ConnectionString = "Data Source=totally_not_my_privateKeys.db;Pooling=True;Max Pool Size=100;Journal Mode=WAL;";

    public static void InitializeDatabase()
    {
        DatabaseHelper.ExecuteWithRetry(() =>
        {
            using var connection = new SQLiteConnection(ConnectionString);
            connection.Open();

            var command = connection.CreateCommand();
            command.CommandText = @"
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                );";
            command.ExecuteNonQuery();
        });
    }

    public static void CreateAndStoreKey(bool expired)
    {
        using var rsa = RSA.Create(2048);
        var expiry = DateTimeOffset.UtcNow.AddHours(expired ? -1 : 1).ToUnixTimeSeconds();
        var pemKey = ExportKeyToPEM(rsa);
        var encryptedKey = EncryptKey(Encoding.UTF8.GetBytes(pemKey));

        DatabaseHelper.ExecuteWithRetry(() =>
        {
            using var connection = new SQLiteConnection(ConnectionString);
            connection.Open();

            var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO keys (key, exp) VALUES (?, ?)";
            command.Parameters.Add(new SQLiteParameter { Value = encryptedKey });
            command.Parameters.Add(new SQLiteParameter { Value = expiry });

            command.ExecuteNonQuery();
        });
    }

    private static byte[] EncryptKey(byte[] privateKey)
    {
        using var aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        cs.Write(privateKey, 0, privateKey.Length);
        cs.Close();

        return ms.ToArray();
    }

    private static string ExportKeyToPEM(RSA rsa)
    {
        var key = rsa.ExportRSAPrivateKey();
        return Convert.ToBase64String(key);
    }
}

[ApiController]
[Route("register")]
public class RegistrationController : ControllerBase
{
    private static readonly string ConnectionString = "Data Source=totally_not_my_privateKeys.db;";

    [HttpPost]
    public IActionResult Register([FromBody] RegistrationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Email))
            return BadRequest("Username and Email are required.");

        string password = Guid.NewGuid().ToString();
        string passwordHash = HashPassword(password);

        try
        {
            DatabaseHelper.ExecuteWithRetry(() =>
            {
                using var connection = new SQLiteConnection(ConnectionString);
                connection.Open();

                var command = connection.CreateCommand();
                command.CommandText = "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)";
                command.Parameters.Add(new SQLiteParameter { Value = request.Username });
                command.Parameters.Add(new SQLiteParameter { Value = passwordHash });
                command.Parameters.Add(new SQLiteParameter { Value = request.Email });

                command.ExecuteNonQuery();
            });

            return Created(string.Empty, new { password });
        }
        catch (SQLiteException ex) when (ex.Message.Contains("UNIQUE constraint failed"))
        {
            return Conflict("Username or email already exists.");
        }
    }

    private string HashPassword(string password)
    {
        var salt = GenerateSalt();
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 8,
            MemorySize = 65536,
            Iterations = 4
        };

        return Convert.ToBase64String(argon2.GetBytes(32));
    }

    private byte[] GenerateSalt()
    {
        byte[] salt = new byte[16];
        using var rng = new RNGCryptoServiceProvider();
        rng.GetBytes(salt);
        return salt;
    }
}

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private static readonly string ConnectionString = "Data Source=totally_not_my_privateKeys.db;";
    private static readonly ConcurrentDictionary<string, int> RateLimiter = new ConcurrentDictionary<string, int>();
    private static readonly TimeSpan RateLimitWindow = TimeSpan.FromSeconds(10);

    [HttpPost]
    public IActionResult Authenticate([FromBody] AuthRequest request)
    {
        var userIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        if (!CheckRateLimit(userIp))
            return StatusCode((int)HttpStatusCode.TooManyRequests, "Rate limit exceeded.");

        using var connection = new SQLiteConnection(ConnectionString);
        connection.Open();

        var userQuery = connection.CreateCommand();
        userQuery.CommandText = "SELECT id, password_hash FROM users WHERE username = ?";
        userQuery.Parameters.Add(new SQLiteParameter { Value = request.Username });

        using var reader = userQuery.ExecuteReader();
        if (!reader.Read())
        {
            LogAuthAttempt(userIp, null);
            return Unauthorized("Invalid username or password.");
        }

        int userId = reader.GetInt32(0);
        string storedHash = reader.GetString(1);

        if (!VerifyPassword(request.Password, storedHash))
        {
            LogAuthAttempt(userIp, userId);
            return Unauthorized("Invalid username or password.");
        }

        LogAuthAttempt(userIp, userId);

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes("SecureKeyq31vJYG9r7TRgmj4ism8pzE4RgqnGt!");

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, request.Username)
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return Ok(new { jwt = tokenHandler.WriteToken(token) });
    }

    private bool CheckRateLimit(string ip)
    {
        var count = RateLimiter.AddOrUpdate(ip, 1, (_, value) => value + 1);
        if (count > 5)
        {
            Thread.Sleep(RateLimitWindow);
            RateLimiter[ip] = 0;
            return false;
        }
        return true;
    }

    private void LogAuthAttempt(string ip, int? userId)
    {
        DatabaseHelper.ExecuteWithRetry(() =>
        {
            using var connection = new SQLiteConnection(ConnectionString);
            connection.Open();

            var logCommand = connection.CreateCommand();
            logCommand.CommandText = "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)";
            logCommand.Parameters.Add(new SQLiteParameter { Value = ip });
            logCommand.Parameters.Add(new SQLiteParameter { Value = userId });

            logCommand.ExecuteNonQuery();
        });
    }

    private bool VerifyPassword(string password, string storedHash)
    {
        return true; // Replace with actual Argon2 password verification logic
    }
}

public class RegistrationRequest
{
    public string Username { get; set; }
    public string Email { get; set; }
}

public class AuthRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}
