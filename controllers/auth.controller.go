package controllers

import (
	"context"
	"os"
	"time"

	"github.com/SudipSarkar1193/AI-powered-Quiz-App-Backend/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)


func Register(c *fiber.Ctx, collection *mongo.Collection) error {
    var user models.User

    if err := c.BodyParser(&user); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "cannot parse JSON"})
    } 
	//⭐⭐ Note : c.BodyParser(&user) takes the incoming JSON data from the request body (which is sent by the frontend when a user submits the registration form) and tries to decode it into the user struct we just initialized.
	
	if  user.Username == "" || user.Email == "" || user.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "All fields must be filled"})
	}
  
    filter := bson.M{"$or": []bson.M{
        {"username": user.Username},
        {"email": user.Email},
    }}

    var existingUser models.User
    err := collection.FindOne(context.Background(), filter).Decode(&existingUser) 
	//⭐⭐ Note : collection.FindOne(...).Decode(&existingUser) checks the database using the filter. If a matching user is found, their data is decoded into the existingUser struct.

    if err == nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "username, or email already in use"})
    } else if err != mongo.ErrNoDocuments {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to check existing user"})
    }

    // Hash the password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to hash password"})
    }
    user.Password = string(hashedPassword)

    // Insert 
    user.ID = primitive.NewObjectID()
    _, err = collection.InsertOne(context.Background(), user)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create user"})
    }

    return c.Status(fiber.StatusCreated).JSON(user)
}


type LoginData struct {
	Username string `json:"username"`
    Email    string `json:"email"`
	Password        string `json:"password"`
}

func Login(c *fiber.Ctx, collection *mongo.Collection) error {
	// Parse login data
	var loginData LoginData
	if err := c.BodyParser(&loginData); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "cannot parse JSON"})
	}

	// Find user by username or email
	filter := bson.M{"$or": []bson.M{
		{"username": loginData.Username},
		{"email": loginData.Email},
	}}
	var user models.User
	err := collection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid username or email"})
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid password"})
	}

	// Check if user is verified
	// if !user.Verified {
	// 	token, err := generateVerificationToken(user.ID, collection)
	// 	if err != nil {
	// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "error creating verification token"})
	// 	}
	// 	verificationURL := fmt.Sprintf("%s/users/%s/verify/%s", os.Getenv("FRONTEND_URL"), user.ID.Hex(), token)
	// 	// Send verification email (pseudo code)
	// 	utils.SendEmail(user.Email, "Verify Your Account", verificationURL)
	// 	return c.Status(200).JSON(fiber.Map{"message": "Verification link sent to your email"})
	// }


	// Generate access and refresh tokens

	accessToken, err := generateAccessToken(user.ID.Hex())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "cannot generate access token"})
	}
	refreshToken, err := generateRefreshToken(user.ID.Hex())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "cannot generate refresh token"})
	}

	// Set tokens in cookies
	c.Cookie(&fiber.Cookie{
		Name:     "accessToken",
		Value:    accessToken,
		MaxAge:   15 * 24 * 60 * 60,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "None",
	})
	c.Cookie(&fiber.Cookie{
		Name:     "refreshToken",
		Value:    refreshToken,
		MaxAge:   15 * 24 * 60 * 60,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "None",
	})

	return c.JSON(fiber.Map{"message": "User successfully logged in"})
}

// Token generation (access and refresh tokens)

func generateAccessToken(userID string) (string, error) {
	claims := jwt.MapClaims{ 
		"userID": userID,
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	} // claims basicaly means information jwt.MapClaims is a type used to store the claims (information) within the token.

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("ACCESS_TOKEN_SECRET")))
}

func generateRefreshToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"userID": userID,
		"exp":    time.Now().Add(time.Hour * 24 * 15).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("REFRESH_TOKEN_SECRET")))
}

// func generateVerificationToken(userID string, collection *mongo.Collection) (string, error) {
// 	token := make([]byte, 32)
// 	_, err := rand.Read(token)
// 	if err != nil {
// 		return "", err
// 	}

// 	// Store the verification token in DB (pseudo code)
// 	verificationToken := models.VerificationToken{
// 		UserID: userID,
// 		Token:  hex.EncodeToString(token),
// 		Expiry: time.Now().Add(24 * time.Hour),
// 	}
// 	_, err = collection.InsertOne(context.Background(), verificationToken)
// 	if err != nil {
// 		return "", err
// 	}

// 	return verificationToken.Token, nil
// }



func GetCurrentUser (ctx *fiber.Ctx, collection *mongo.Collection) error {
    user_id , ok:= ctx.Locals("userID").(string)

    if !ok || user_id == "" {
        return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid or missing user ID",
        })
    }

    // In ctx.Locals userId is stored as String 
    // We newwd to convert it from hexSting
    userId,err := primitive.ObjectIDFromHex(user_id)

    if err != nil {
		return ctx.Status(400).JSON(fiber.Map{"error": "Invalid user ID"})
	}

    var user models.User 
  
    filter := bson.M{"_id": userId}

    err = collection.FindOne(context.Background(), filter).Decode(&user)
    if err != nil {
        if err == mongo.ErrNoDocuments {
            return ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{
                "error": "User not found",
            })
        }
        return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Internal server error",
        })
    }

    return ctx.Status(200).JSON(user)
}
