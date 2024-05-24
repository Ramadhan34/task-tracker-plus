package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		tokenString, err := ctx.Cookie("session_token")

		header := ctx.GetHeader("Content-Type")

		if header == "application/json" {
			if err != nil {
				ctx.JSON(http.StatusUnauthorized, model.ErrorResponse{Error: "error token is missing"})
				return
			}
		}

		if tokenString == "" {
			ctx.JSON(http.StatusSeeOther, model.ErrorResponse{Error: "error retrieving from cookie"})
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &model.Claims{}, func(token *jwt.Token) (any, error) {
			return model.JwtKey, nil
		})

		if err != nil {
			ctx.JSON(http.StatusBadRequest, model.ErrorResponse{Error: err.Error()})
			return
		}

		claims, ok := token.Claims.(*model.Claims)
		if !ok || !token.Valid {
			ctx.JSON(http.StatusUnauthorized, model.ErrorResponse{Error: "error not ok and not valid"})
			return
		}

		ctx.Set("email", claims.Email)

		ctx.Next() // TODO: answer here
	})
}
