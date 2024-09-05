package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)


type User struct {
    ID        primitive.ObjectID `bson:"_id,omitempty"`
    Username  string             `bson:"username,omitempty" validate:"required"`
    Email     string             `bson:"email,omitempty" validate:"required"`
    Password  string             `bson:"password,omitempty" validate:"required"`
    
}




type ReqData struct {

    Topic  string             `bson:"topic,omitempty" `
    Difficulty  string             `bson:"difficulty,omitempty" `
    Num     int             `bson:"number,omitempty"`

    
}