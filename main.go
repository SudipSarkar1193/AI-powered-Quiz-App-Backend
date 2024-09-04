package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/SudipSarkar1193/AI-powered-Quiz-App-Backend/routes"
	"github.com/SudipSarkar1193/AI-powered-Quiz-App-Backend/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
    "github.com/gofiber/fiber/v2/middleware/cors"
)


func main() {
    fmt.Println("Welcome !")
        // Initialize Fiber
    fiberApp := fiber.New()
    fiberApp.Use(cors.New(cors.Config{
        AllowOrigins:  "http://localhost:5175", // Replace with your frontend URL
        AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
        AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
        AllowCredentials: true,
	}))
    // if err := godotenv.Load(".env"); err != nil {
    //     log.Fatal(err)
    // }

    client, msg, err := connectDb()
    if err != nil {
        log.Fatalf("Error connecting to the database: %v", err)
    }
    fmt.Println(msg)

    defer func() {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        if err := client.Disconnect(ctx); err != nil {
            log.Fatalf("Error disconnecting from the database: %v", err)
        }
    }()

    db := client.Database("Quiz-App-with-AI")

    userCollection := db.Collection("users")

    // Create an instance of App with dependencies
    app := &utils.App{
        UserDBCollection: userCollection,
    }




    routes.SetupAuthRoutes(fiberApp,app)
    routes.SetupDataRoutes(fiberApp)


    port := os.Getenv("PORT")
    if port == "" {
        port = "8000"
    }

    log.Fatal(fiberApp.Listen("0.0.0.0:" + port))
}

func connectDb() (*mongo.Client, string, error) {
    dbName := os.Getenv("DB_NAME")
    mongoURI := os.Getenv("MONGO_URI")

    clientOptions := options.Client().ApplyURI(mongoURI)
    client, err := mongo.Connect(context.Background(), clientOptions)
    if err != nil {
        return nil, "", fmt.Errorf("failed to create a client: %w", err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
    defer cancel()

    err = client.Ping(ctx, nil)
    if err != nil {
        return nil, "", fmt.Errorf("failed to ping the database: %w", err)
    }

    return client, "Connected to Database: " + dbName, nil
}
