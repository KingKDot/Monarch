package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"Monarch/internal/av"
	"Monarch/internal/config"
	"Monarch/internal/db"
	"Monarch/internal/scan"
	"Monarch/internal/web"
)

func Run() error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	database, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer database.Close()

	if err := db.EnsureSchema(ctx, database); err != nil {
		return err
	}

	avTargets, err := av.LoadTargets(cfg.AVConfigPath)
	if err != nil {
		return err
	}
	if len(avTargets) == 0 {
		return errors.New("no AV targets configured (set MONARCH_AV_CONFIG)")
	}

	secret := cfg.CookieSecret
	if secret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		secret = hex.EncodeToString(b)
		fmt.Fprintln(os.Stderr, "warning: MONARCH_COOKIE_SECRET not set; generated ephemeral secret (logins will reset on restart)")
	}

	scanner := scan.NewService(scan.ServiceConfig{
		StorageDir:     cfg.StorageDir,
		MaxUploadBytes: cfg.MaxUploadBytes,
		ScanWait:       cfg.ScanWait,
		WinRMUser:      cfg.WinRMUser,
		WinRMPass:      cfg.WinRMPass,
		WinRMUseHTTPS:  cfg.WinRMUseHTTPS,
		WinRMInsecure:  cfg.WinRMInsecure,
		WinRMPort:      cfg.WinRMPort,
		AVTargets:      avTargets,
		Database:       database,
		WorkerCount:    cfg.WorkerCount,
		RequireCaptcha: cfg.RequireCaptchaScan,
		CaptchaThresh:  cfg.CaptchaThreshold,
		CaptchaWindow:  cfg.CaptchaWindow,
		CaptchaSiteKey: cfg.CaptchaSiteKey,
		CaptchaSecret:  cfg.CaptchaSecret,
	})
	defer scanner.Close()

	router, err := web.NewRouter(web.RouterConfig{
		Database:       database,
		CookieSecret:   secret,
		MaxUploadBytes: cfg.MaxUploadBytes,
		RequireCaptcha: cfg.RequireCaptchaAuth,
		CaptchaThresh:  cfg.CaptchaThreshold,
		CaptchaWindow:  cfg.CaptchaWindow,
		AdminUser:      cfg.AdminUser,
		AdminPass:      cfg.AdminPass,
		Scanner:        scanner,
		PublicBaseURL:  cfg.PublicBaseURL,
		CSRFProtection: false,
		SameSiteStrict: true,
		SecureCookies:  cfg.SecureCookies,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "listening on %s\n", cfg.ListenAddr)
	return srv.ListenAndServe()
}
