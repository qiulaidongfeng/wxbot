package main

import "github.com/gin-gonic/gin"

func main() {
	s := gin.Default()
	err := s.RunTLS(":443", "./cert.pem", "./key.pem")
	if err != nil {
		println(err.Error())
	}
}
