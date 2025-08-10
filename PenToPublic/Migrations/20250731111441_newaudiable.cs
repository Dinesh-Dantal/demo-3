using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PenToPublic.Migrations
{
    /// <inheritdoc />
    public partial class newaudiable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_User_Registration_RegId",
                table: "User");

            migrationBuilder.AddColumn<int>(
                name: "TotalPages",
                table: "ReadingProgress",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<bool>(
                name: "IsAudible",
                table: "Book",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddForeignKey(
                name: "FK_User_Registration_RegId",
                table: "User",
                column: "RegId",
                principalTable: "Registration",
                principalColumn: "RegId",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_User_Registration_RegId",
                table: "User");

            migrationBuilder.DropColumn(
                name: "TotalPages",
                table: "ReadingProgress");

            migrationBuilder.DropColumn(
                name: "IsAudible",
                table: "Book");

            migrationBuilder.AddForeignKey(
                name: "FK_User_Registration_RegId",
                table: "User",
                column: "RegId",
                principalTable: "Registration",
                principalColumn: "RegId");
        }
    }
}
