package service

// Subscriber-facing password rotation. The subscription page is the only caller:
// an account holder who knows the current credential may replace it without
// going through an operator. The write goes through the same projection every
// other account edit uses, so all member inbounds pick the new password up
// atomically.

import (
	"errors"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"gorm.io/gorm"
)

// Sentinel errors the subscription handler maps to localized messages.
var (
	ErrSubAccountNotFound = errors.New("account not found")
	ErrSubWrongPassword   = errors.New("current password is incorrect")
	ErrSubWeakPassword    = errors.New("new password is too short")
)

// MinSubscriberPasswordLength mirrors the panel form's own floor.
const MinSubscriberPasswordLength = 6

// ChangeSubscriberPassword verifies currentPassword against the account's
// stored password, replaces it with newPassword, and re-projects the account
// onto every inbound that serves it. It returns the inbound ids whose settings
// changed, for the caller's reconcile (Xray restart / daemon regeneration).
func (s *AccountService) ChangeSubscriberPassword(email, currentPassword, newPassword string) ([]int, error) {
	key := accountKey(email)
	if key == "" {
		return nil, common.NewError("no email")
	}
	newPassword = strings.TrimSpace(newPassword)
	if len(newPassword) < MinSubscriberPasswordLength {
		return nil, ErrSubWeakPassword
	}

	var touched []int
	err := database.GetDB().Transaction(func(tx *gorm.DB) error {
		account, err := s.GetAccountByEmailTx(tx, email)
		if err != nil {
			return err
		}
		if account == nil {
			return ErrSubAccountNotFound
		}
		if account.Password != currentPassword {
			return ErrSubWrongPassword
		}
		if err := tx.Model(&model.Account{}).Where("id = ?", account.Id).
			Update("password", newPassword).Error; err != nil {
			return err
		}
		changed, err := s.ProjectAccount(tx, account.Id)
		if err != nil {
			return err
		}
		touched = changed
		for _, inboundId := range changed {
			if err := s.SyncInboundAccounts(tx, inboundId, 0); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return touched, nil
}
