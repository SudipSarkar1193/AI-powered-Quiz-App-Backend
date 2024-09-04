package routes

import (
	"github.com/SudipSarkar1193/AI-powered-Quiz-App-Backend/controllers"
	"github.com/SudipSarkar1193/AI-powered-Quiz-App-Backend/middlewares"
	"github.com/SudipSarkar1193/AI-powered-Quiz-App-Backend/utils"
	"github.com/gofiber/fiber/v2"
)

func SetupAuthRoutes(app *fiber.App, appInstance *utils.App) {
	auth := app.Group("/api/auth")

	auth.Post("/login", func(c *fiber.Ctx) error {
		return controllers.Login(c, appInstance.UserDBCollection)
	})
	auth.Post("/signup", func(c *fiber.Ctx) error {
		return controllers.Register(c, appInstance.UserDBCollection)
	})

	getmeRoute := app.Group("/api/auth", middlewares.AuthenticateUser)

	getmeRoute.Get("/me", func(c *fiber.Ctx) error {
		return controllers.GetCurrentUser(c, appInstance.UserDBCollection)
	})
}
