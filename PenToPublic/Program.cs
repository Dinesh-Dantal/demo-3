using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using PenToPublic.Data;
using PenToPublic.Models;
using PenToPublic.Services;
using System.Text;
using AutoMapper;

var builder = WebApplication.CreateBuilder(args);

// ➤ Database Configuration
builder.Services.AddDbContext<PenToPublicContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("PenToPublicContext")
        ?? throw new InvalidOperationException("Connection string not found.")
    )
);

// ➤ Email Service for OTP (Forgot Password)
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
builder.Services.AddScoped<EmailService>();

// ➤ AutoMapper
builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

// ➤ Razorpay Integration
builder.Services.AddScoped<RazorpayService>();

// ➤ Authentication using JWT
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSettings["Key"]);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ClockSkew = TimeSpan.Zero
        };
    });

// ➤ Authorization
builder.Services.AddAuthorization();

// ➤ CORS for Frontend (React CRA or Vite)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()   // <-- Allows requests from any origin
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});


// ➤ Swagger with JWT Token UI
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "PenToPublic API",
        Version = "v1"
    });

    // Add JWT Auth to Swagger
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

// ➤ Add Controllers
builder.Services.AddControllers();

// ➤ Build & Configure HTTP Pipeline
var app = builder.Build();

// ➤ Middleware
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
