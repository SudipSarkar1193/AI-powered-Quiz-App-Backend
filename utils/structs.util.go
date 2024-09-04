package utils

import (
    "go.mongodb.org/mongo-driver/mongo"
)

type App struct {
    UserDBCollection *mongo.Collection
};
//Dependency Injection
