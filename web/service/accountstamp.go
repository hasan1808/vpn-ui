package service

import (
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// StampCreatedBy backfills the creator on accounts that were just created but
// whose write path synced with createdBy=0 (the BULK add path does: one request
// carries many clients and no single creator-aware sync). Only rows with no
// creator yet are touched, so an earlier real creator is never overwritten.
// Best-effort metadata: a failed stamp must not fail the client write that
// already succeeded.
func (s *AccountService) StampCreatedBy(emails []string, userId int) {
	if userId <= 0 || len(emails) == 0 {
		return
	}
	normalized := make([]string, 0, len(emails))
	for _, e := range emails {
		if k := AccountKeyOf(e); k != "" {
			normalized = append(normalized, k)
		}
	}
	if len(normalized) == 0 {
		return
	}
	err := database.GetDB().Model(&model.Account{}).
		Where("created_by = 0 AND LOWER(TRIM(email)) IN ?", normalized).
		Update("created_by", userId).Error
	if err != nil {
		logger.Warning("stamping account creator: ", err)
	}
}
