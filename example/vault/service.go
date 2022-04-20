package vault

import (
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
)

type vaultService struct{}

type Service interface {
	Hash(ctx context.Context, password string) (string, error)
	Validate(ctx context.Context, password, hash string) (bool, error)
}

func NewService() Service {
	return vaultService{}
}

func (vaultService) Hash(ctx context.Context, passowrd string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(passowrd), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (vaultService) Validate(ctx context.Context, password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false, nil
	}
	return true, nil
}
