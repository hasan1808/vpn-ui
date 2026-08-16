package service

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/crypto"
	ldaputil "github.com/hasan1808/pro-ui/util/ldap"
	"github.com/xlzd/gotp"
	"gorm.io/gorm"
)

// UserService provides business logic for user management and authentication.
// It handles user creation, login, password management, and 2FA operations.
type UserService struct {
	settingService SettingService
}

// GetFirstUser retrieves the first user from the database.
// This is typically used for initial setup or when there's only one admin user.
func (s *UserService) GetFirstUser() (*model.User, error) {
	db := database.GetDB()

	user := &model.User{}
	err := db.Model(model.User{}).
		First(user).
		Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) CheckUser(username string, password string, twoFactorCode string) (*model.User, error) {
	db := database.GetDB()

	user := &model.User{}

	err := db.Model(model.User{}).
		Where("username = ?", username).
		First(user).
		Error
	if err == gorm.ErrRecordNotFound {
		return nil, errors.New("invalid credentials")
	} else if err != nil {
		logger.Warning("check user err:", err)
		return nil, err
	}

	if !crypto.CheckPasswordHash(user.Password, password) {
		ldapEnabled, _ := s.settingService.GetLdapEnable()
		if !ldapEnabled {
			return nil, errors.New("invalid credentials")
		}

		host, _ := s.settingService.GetLdapHost()
		port, _ := s.settingService.GetLdapPort()
		useTLS, _ := s.settingService.GetLdapUseTLS()
		bindDN, _ := s.settingService.GetLdapBindDN()
		ldapPass, _ := s.settingService.GetLdapPassword()
		baseDN, _ := s.settingService.GetLdapBaseDN()
		userFilter, _ := s.settingService.GetLdapUserFilter()
		userAttr, _ := s.settingService.GetLdapUserAttr()

		cfg := ldaputil.Config{
			Host:       host,
			Port:       port,
			UseTLS:     useTLS,
			BindDN:     bindDN,
			Password:   ldapPass,
			BaseDN:     baseDN,
			UserFilter: userFilter,
			UserAttr:   userAttr,
		}
		ok, err := ldaputil.AuthenticateUser(cfg, username, password)
		if err != nil || !ok {
			return nil, errors.New("invalid credentials")
		}
	}

	// A disabled admin authenticates correctly but must not get a session. Checked
	// after the password so a disabled account is indistinguishable from a wrong
	// one, rather than confirming the username exists.
	if !user.Enable {
		return nil, errors.New("invalid credentials")
	}

	// TOTP is per-admin: each admin's secret lives on their own row. It used to be
	// one panel-wide secret in the settings table, which GetAllSetting handed to
	// every logged-in user, so any admin could pass any other admin's 2FA.
	if user.TwoFactorEnable {
		if !verifyTOTP(user.TwoFactorToken, twoFactorCode) {
			return nil, ErrInvalidTwoFactorCode
		}
	}

	return user, nil
}

// ErrInvalidTwoFactorCode is sentinel rather than a bare string: the login handler
// branches on it to tell the user their password was fine but their code wasn't,
// and it used to do that by comparing err.Error() to a literal.
var ErrInvalidTwoFactorCode = errors.New("invalid 2fa code")

// totpSkewWindows accepts the adjacent 30s windows either side of now. The old
// check compared only against the current window, so a few seconds of drift on the
// phone or the server locked the admin out with no way back in.
var totpSkewWindows = []int64{-30, 0, 30}

// VerifyTOTPCode checks a code against a secret that is not stored yet, for
// enrolment: a secret the admin cannot actually produce codes for must never be
// saved, or they lock themselves out of their own account.
func VerifyTOTPCode(secret, code string) bool { return verifyTOTP(secret, code) }

// verifyTOTP checks code against secret in constant time across the skew window.
func verifyTOTP(secret, code string) bool {
	if secret == "" || code == "" {
		return false
	}
	totp := gotp.NewDefaultTOTP(secret)
	now := time.Now().Unix()
	ok := false
	for _, offset := range totpSkewWindows {
		// No early return: compare every window so the time taken doesn't reveal
		// which one matched.
		if subtle.ConstantTimeCompare([]byte(totp.At(now+offset)), []byte(code)) == 1 {
			ok = true
		}
	}
	return ok
}

func (s *UserService) UpdateUser(id int, username string, password string) error {
	db := database.GetDB()
	hashedPassword, err := crypto.HashPasswordAsBcrypt(password)

	if err != nil {
		return err
	}

	// Changing credentials clears THIS admin's TOTP, so a lost authenticator can be
	// recovered by a password change. It used to clear the panel-global 2FA setting,
	// so one admin renaming themselves disabled 2FA for everyone.
	return db.Model(model.User{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"username":          username,
			"password":          hashedPassword,
			"two_factor_enable": false,
			"two_factor_token":  "",
		}).
		Error
}

func (s *UserService) UpdateFirstUser(username string, password string) error {
	if username == "" {
		return errors.New("username can not be empty")
	} else if password == "" {
		return errors.New("password can not be empty")
	}
	hashedPassword, er := crypto.HashPasswordAsBcrypt(password)

	if er != nil {
		return er
	}

	db := database.GetDB()
	user := &model.User{}
	err := db.Model(model.User{}).First(user).Error
	if database.IsNotFound(err) {
		user.Username = username
		user.Password = hashedPassword
		// Seeding from scratch (CLI recovery): must be a usable super admin, or the
		// panel comes up with an account that cannot manage anything.
		user.IsSuperAdmin = true
		user.Enable = true
		return db.Model(model.User{}).Create(user).Error
	} else if err != nil {
		return err
	}
	user.Username = username
	user.Password = hashedPassword
	return db.Save(user).Error
}

// SetFirstUsername changes ONLY the first user's login username, preserving the
// existing (already-hashed) password. Used by `vpn-ui --user <name>` when no
// --pass is given, so an operator can rename the admin without re-supplying the
// password.
func (s *UserService) SetFirstUsername(username string) error {
	if username == "" {
		return errors.New("username can not be empty")
	}
	db := database.GetDB()
	user := &model.User{}
	if err := db.Model(model.User{}).First(user).Error; err != nil {
		return err
	}
	user.Username = username
	return db.Save(user).Error
}

// SetTwoFactor enables or disables one admin's TOTP.
//
// Per-admin, not panel-wide: the old global secret lived in the settings table,
// which GetAllSetting handed to every logged-in user, so any admin could read it
// and pass any other admin's second factor.
func (s *UserService) SetTwoFactor(userId int, enable bool, token string) error {
	updates := map[string]any{"two_factor_enable": false, "two_factor_token": ""}
	if enable {
		if token == "" {
			return errors.New("a two-factor secret is required")
		}
		updates["two_factor_enable"] = true
		updates["two_factor_token"] = token
	}
	return database.GetDB().Model(model.User{}).Where("id = ?", userId).Updates(updates).Error
}
