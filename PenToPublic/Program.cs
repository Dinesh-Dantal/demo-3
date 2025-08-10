using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using PenToPublic.Data;
using PenToPublic.Models;
using PenToPublic.Services;
using AutoMapper;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------
// Database Configuration (MSSQL)
// ---------------------------------------
var dbConn = Environment.GetEnvironmentVariable("DB_CONNECTION")
             ?? builder.Configuration.GetConnectionString("PenToPublicContext");

if (string.IsNullOrWhiteSpace(dbConn))
{
    throw new InvalidOperationException("❌ Database connection string not found. Set DB_CONNECTION env var.");
}

builder.Services.AddDbContext<PenToPublicContext>(options =>
    options.UseSqlServer(dbConn)
);

// ---------------------------------------
// Email Service (SMTP for OTP / Forgot Password)
// ---------------------------------------
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
builder.Services.PostConfigure<SmtpSettings>(smtp =>
{
    smtp.Host = Environment.GetEnvironmentVariable("SMTP_HOST") ?? smtp.Host;
    smtp.Port = int.TryParse(Environment.GetEnvironmentVariable("SMTP_PORT"), out var port) ? port : smtp.Port;
    smtp.SenderEmail = Environment.GetEnvironmentVariable("SMTP_EMAIL") ?? smtp.SenderEmail;
    smtp.SenderName = Environment.GetEnvironmentVariable("SMTP_NAME") ?? smtp.SenderName;
    smtp.Username = Environment.GetEnvironmentVariable("SMTP_USERNAME") ?? smtp.Username;
    smtp.Password = Environment.GetEnvironmentVariable("SMTP_PASSWORD") ?? smtp.Password;
});
builder.Services.AddScoped<EmailService>();

// ---------------------------------------
// AutoMapper
// ---------------------------------------
builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

// ---------------------------------------
// Razorpay Service
// ---------------------------------------
builder.Services.Configure<RazorpaySettings>(builder.Configuration.GetSection("Razorpay"));
builder.Services.PostConfigure<RazorpaySettings>(rzp =>
{
    rzp.Key = Environment.GetEnvironmentVariable("RAZORPAY_KEY") ?? rzp.Key;
    rzp.Secret = Environment.GetEnvironmentVariable("RAZORPAY_SECRET") ?? rzp.Secret;
});
builder.Services.AddScoped<RazorpayService>();

// ---------------------------------------
// JWT Authentication
// ---------------------------------------
var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY")
             ?? builder.Configuration["Jwt:Key"];
var jwtIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER")
                ?? builder.Configuration["Jwt:Issuer"];
var jwtAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE")
                  ?? builder.Configuration["Jwt:Audience"];

if (string.IsNullOrWhiteSpace(jwtKey))
    throw new InvalidOperationException("❌ JWT_KEY is required for authentication.");

var keyBytes = Encoding.UTF8.GetBytes(jwtKey);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false; // Set true in production with HTTPS
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

// ---------------------------------------
// CORS (currently open — adjust for prod)
// ---------------------------------------
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

// ---------------------------------------
// Swagger + JWT Auth
// ---------------------------------------
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "PenToPublic API",
        Version = "v1"
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer {token}'",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme {
                Reference = new OpenApiReference {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ---------------------------------------
// Controllers
// ---------------------------------------
builder.Services.AddControllers();

// ---------------------------------------
// Build & Middleware Pipeline
// ---------------------------------------
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
