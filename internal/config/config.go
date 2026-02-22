package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr string

	DatabaseURL  string
	AVConfigPath string
	StorageDir   string

	CookieSecret  string
	SecureCookies bool

	AdminUser string
	AdminPass string

	MaxUploadBytes int64
	ScanWait       time.Duration
	WorkerCount    int

	WinRMUser     string
	WinRMPass     string
	WinRMPort     int
	WinRMUseHTTPS bool
	WinRMInsecure bool

	RequireCaptchaAuth bool
	RequireCaptchaScan bool
	CaptchaThreshold   int
	CaptchaWindow      time.Duration

	CaptchaSiteKey string
	CaptchaSecret  string

	PublicBaseURL string
}

func LoadFromEnv() (Config, error) {
	cfg := Config{}

	cfg.ListenAddr = envDefault("MONARCH_LISTEN", ":8080")
	cfg.DatabaseURL = os.Getenv("MONARCH_DATABASE_URL")
	cfg.AVConfigPath = envDefault("MONARCH_AV_CONFIG", "avs.json")
	cfg.StorageDir = envDefault("MONARCH_STORAGE_DIR", "storage")
	cfg.CookieSecret = os.Getenv("MONARCH_COOKIE_SECRET")
	cfg.SecureCookies = envBoolDefault("MONARCH_SECURE_COOKIES", false)

	cfg.AdminUser = envDefault("MONARCH_ADMIN_USER", "")
	cfg.AdminPass = envDefault("MONARCH_ADMIN_PASS", "")

	// Default: 35 MiB
	cfg.MaxUploadBytes = envInt64Default("MONARCH_MAX_UPLOAD_BYTES", 35*1024*1024)
	cfg.ScanWait = envDurationDefault("MONARCH_SCAN_WAIT", 15*time.Second)
	cfg.WorkerCount = envIntDefault("MONARCH_WORKERS", 2)

	cfg.WinRMUser = os.Getenv("MONARCH_WINRM_USER")
	cfg.WinRMPass = os.Getenv("MONARCH_WINRM_PASS")
	cfg.WinRMPort = envIntDefault("MONARCH_WINRM_PORT", 5985)
	cfg.WinRMUseHTTPS = envBoolDefault("MONARCH_WINRM_HTTPS", false)
	cfg.WinRMInsecure = envBoolDefault("MONARCH_WINRM_INSECURE", true)

	cfg.RequireCaptchaAuth = envBoolDefault("MONARCH_CAPTCHA_AUTH", true)
	cfg.RequireCaptchaScan = envBoolDefault("MONARCH_CAPTCHA_SCAN", false)
	cfg.CaptchaThreshold = envIntDefault("MONARCH_CAPTCHA_THRESHOLD", 10)
	cfg.CaptchaWindow = envDurationDefault("MONARCH_CAPTCHA_WINDOW", 2*time.Minute)

	cfg.CaptchaSiteKey = os.Getenv("MONARCH_CAPTCHA_SITE_KEY")
	cfg.CaptchaSecret = os.Getenv("MONARCH_CAPTCHA_SECRET")

	cfg.PublicBaseURL = envDefault("MONARCH_PUBLIC_BASE_URL", "")

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("MONARCH_DATABASE_URL is required")
	}
	if cfg.WinRMUser == "" || cfg.WinRMPass == "" {
		return Config{}, errors.New("MONARCH_WINRM_USER and MONARCH_WINRM_PASS are required")
	}
	if cfg.WorkerCount < 1 {
		cfg.WorkerCount = 1
	}
	if cfg.CaptchaThreshold < 1 {
		cfg.CaptchaThreshold = 1
	}

	return cfg, nil
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBoolDefault(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envIntDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envInt64Default(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func envDurationDefault(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
