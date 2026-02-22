package web

import (
	"embed"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"Monarch/internal/auth"
	"Monarch/internal/ratelimit"
	"Monarch/internal/scan"

	"github.com/dchest/captcha"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed templates/*.html assets/*
var templatesFS embed.FS

type RouterConfig struct {
	Database       *pgxpool.Pool
	CookieSecret   string
	MaxUploadBytes int64
	RequireCaptcha bool
	CaptchaThresh  int
	CaptchaWindow  time.Duration
	AdminUser      string
	AdminPass      string
	Scanner        *scan.Service
	PublicBaseURL  string
	CSRFProtection bool
	SameSiteStrict bool
	SecureCookies  bool
}

func NewRouter(cfg RouterConfig) (http.Handler, error) {
	if cfg.Database == nil {
		return nil, errors.New("db required")
	}
	if cfg.CookieSecret == "" {
		return nil, errors.New("cookie secret required")
	}
	if cfg.Scanner == nil {
		return nil, errors.New("scanner required")
	}

	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	renderHTML := func(c *gin.Context, status int, name string, data any) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		if err := tmpl.ExecuteTemplate(c.Writer, name, data); err != nil {
			_ = c.Error(err)
		}
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// Static assets (embedded)
	r.GET("/static/style.css", func(c *gin.Context) {
		c.Header("Content-Type", "text/css; charset=utf-8")
		c.Header("Cache-Control", "public, max-age=86400")
		b, err := templatesFS.ReadFile("assets/style.css")
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Writer.Write(b)
	})
	r.MaxMultipartMemory = cfg.MaxUploadBytes

	// Enforce max request size (defense-in-depth in addition to per-file checks).
	r.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, cfg.MaxUploadBytes)
		c.Next()
	})

	activity := ratelimit.NewWindowCounter(cfg.CaptchaWindow, cfg.CaptchaThresh)

	setUser := func(c *gin.Context) {
		cookie, err := c.Cookie("monarch")
		if err == nil {
			if accountID, ok := auth.VerifyCookie(cfg.CookieSecret, cookie); ok {
				c.Set("account_id", accountID)
			}
		}
		c.Next()
	}
	r.Use(setUser)

	r.GET("/", func(c *gin.Context) {
		accountID, _ := c.Get("account_id")
		type recentScan struct {
			ID       string
			Status   string
			Filename string
			SHA256   string
			Created  string
		}
		var recentScans []recentScan
		if accountID != nil {
			rows, err := cfg.Database.Query(c, `
SELECT s.id, s.status, s.original_filename, s.sha256, s.created_at
FROM scans s
JOIN users u ON u.id = s.user_id
WHERE u.account_id = $1
ORDER BY s.created_at DESC LIMIT 20`, accountID)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var it recentScan
					var created time.Time
					_ = rows.Scan(&it.ID, &it.Status, &it.Filename, &it.SHA256, &created)
					it.Created = created.Format("Jan 2, 2006 15:04")
					recentScans = append(recentScans, it)
				}
			}
		}
		renderHTML(c, http.StatusOK, "index.html", gin.H{
			"AccountID":      accountID,
			"RequireCaptcha": cfg.Scanner.CaptchaEnabled(),
			"RecentScans":    recentScans,
		})
	})

	r.GET("/hash", func(c *gin.Context) {
		sha := c.Query("sha")
		if sha == "" {
			c.Redirect(http.StatusSeeOther, "/")
			return
		}
		c.Redirect(http.StatusSeeOther, "/hash/"+sha)
	})

	r.GET("/signup", func(c *gin.Context) {
		renderHTML(c, http.StatusOK, "signup.html", gin.H{"RequireCaptcha": cfg.RequireCaptcha})
	})

	r.POST("/signup", func(c *gin.Context) {
		ip := c.ClientIP()
		_, over := activity.Increment("signup:"+ip, time.Now())
		requireCaptcha := cfg.RequireCaptcha || over
		if requireCaptcha {
			id := c.PostForm("captcha_id")
			sol := c.PostForm("captcha_solution")
			if !captcha.VerifyString(id, sol) {
				renderHTML(c, http.StatusBadRequest, "signup.html", gin.H{"Error": "captcha failed", "RequireCaptcha": cfg.RequireCaptcha})
				return
			}
		}

		password := c.PostForm("password")
		accountID, err := auth.NewAccountID()
		if err != nil {
			c.String(500, "error")
			return
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			renderHTML(c, http.StatusBadRequest, "signup.html", gin.H{"Error": err.Error(), "RequireCaptcha": cfg.RequireCaptcha})
			return
		}

		_, err = cfg.Database.Exec(c, `INSERT INTO users (account_id, password_hash) VALUES ($1,$2)`, accountID, hash)
		if err != nil {
			renderHTML(c, http.StatusBadRequest, "signup.html", gin.H{"Error": "account creation failed", "RequireCaptcha": cfg.RequireCaptcha})
			return
		}

		cookie := auth.SignCookie(cfg.CookieSecret, accountID)
		setCookie(c, cfg, cookie)
		c.Redirect(http.StatusSeeOther, "/")
	})

	r.GET("/login", func(c *gin.Context) {
		renderHTML(c, http.StatusOK, "login.html", gin.H{
			"RequireCaptcha": cfg.RequireCaptcha,
		})
	})

	r.POST("/login", func(c *gin.Context) {
		ip := c.ClientIP()
		_, over := activity.Increment("login:"+ip, time.Now())
		requireCaptcha := cfg.RequireCaptcha && over
		if requireCaptcha {
			id := c.PostForm("captcha_id")
			sol := c.PostForm("captcha_solution")
			if !captcha.VerifyString(id, sol) {
				renderHTML(c, http.StatusBadRequest, "login.html", gin.H{"Error": "captcha failed", "RequireCaptcha": cfg.RequireCaptcha})
				return
			}
		}

		accountID := c.PostForm("account_id")
		password := c.PostForm("password")
		var userID int64
		var stored []byte
		err := cfg.Database.QueryRow(c, `SELECT id, password_hash FROM users WHERE account_id=$1`, accountID).Scan(&userID, &stored)
		if err != nil {
			renderHTML(c, http.StatusBadRequest, "login.html", gin.H{"Error": "invalid credentials", "RequireCaptcha": cfg.RequireCaptcha})
			return
		}
		ok, _ := auth.VerifyPassword(password, stored)
		if !ok {
			renderHTML(c, http.StatusBadRequest, "login.html", gin.H{"Error": "invalid credentials", "RequireCaptcha": cfg.RequireCaptcha})
			return
		}

		cookie := auth.SignCookie(cfg.CookieSecret, accountID)
		setCookie(c, cfg, cookie)
		c.Redirect(http.StatusSeeOther, "/")
	})

	r.POST("/logout", func(c *gin.Context) {
		c.SetCookie("monarch", "", -1, "/", "", cfg.SecureCookies, true)
		c.Redirect(http.StatusSeeOther, "/")
	})

	r.GET("/captcha/new", func(c *gin.Context) {
		c.JSON(200, gin.H{"id": captcha.New()})
	})
	r.GET("/captcha/:id.png", func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			id = c.Param("id.png")
		}
		id = strings.TrimSuffix(id, ".png")
		if id == "" {
			c.Status(http.StatusNotFound)
			return
		}
		c.Header("Cache-Control", "no-store")
		captcha.WriteImage(c.Writer, id, 240, 80)
	})

	authRequired := func(c *gin.Context) {
		if _, ok := c.Get("account_id"); !ok {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}
		c.Next()
	}

	r.POST("/scan", authRequired, func(c *gin.Context) {
		accountID, _ := c.Get("account_id")
		ip := c.ClientIP()
		if cfg.Scanner.ShouldRequireCaptcha(ip, time.Now()) {
			id := c.PostForm("captcha_id")
			sol := c.PostForm("captcha_solution")
			if !captcha.VerifyString(id, sol) {
				renderHTML(c, http.StatusBadRequest, "index.html", gin.H{"Error": "captcha failed", "AccountID": accountID})
				return
			}
		}

		var userID int64
		err := cfg.Database.QueryRow(c, `SELECT id FROM users WHERE account_id=$1`, accountID.(string)).Scan(&userID)
		if err != nil {
			renderHTML(c, http.StatusBadRequest, "index.html", gin.H{"Error": "invalid user", "AccountID": accountID})
			return
		}

		file, err := c.FormFile("file")
		if err != nil {
			renderHTML(c, http.StatusBadRequest, "index.html", gin.H{"Error": "missing file", "AccountID": accountID})
			return
		}
		scanID, err := cfg.Scanner.EnqueueScan(c, userID, file)
		if err != nil {
			renderHTML(c, http.StatusBadRequest, "index.html", gin.H{"Error": err.Error(), "AccountID": accountID})
			return
		}
		c.Redirect(http.StatusSeeOther, "/scan/"+scanID.String())
	})

	// Public: scan result pages are visible to anyone.
	r.GET("/scan/:id", func(c *gin.Context) {
		scanID := c.Param("id")
		var status, filename, sha string
		err := cfg.Database.QueryRow(c, `SELECT status, original_filename, sha256 FROM scans WHERE id=$1`, scanID).Scan(&status, &filename, &sha)
		if err != nil {
			c.String(404, "not found")
			return
		}
		type row struct {
			AV      string
			Status  string
			Deleted *bool
			Updated time.Time
		}
		rows, _ := cfg.Database.Query(c, `SELECT av_name, status, deleted, updated_at FROM scan_results WHERE scan_id=$1 ORDER BY av_name`, scanID)
		defer rows.Close()
		var results []row
		for rows.Next() {
			var r row
			_ = rows.Scan(&r.AV, &r.Status, &r.Deleted, &r.Updated)
			results = append(results, r)
		}

		renderHTML(c, http.StatusOK, "scan.html", gin.H{
			"ScanID":   scanID,
			"Status":   status,
			"Filename": filename,
			"SHA256":   sha,
			"Results":  results,
		})
	})

	// Public: scan JSON is visible to anyone.
	r.GET("/api/scan/:id", func(c *gin.Context) {
		scanID := c.Param("id")
		var status, filename, sha string
		err := cfg.Database.QueryRow(c, `SELECT status, original_filename, sha256 FROM scans WHERE id=$1`, scanID).Scan(&status, &filename, &sha)
		if err != nil {
			c.JSON(404, gin.H{"error": "not found"})
			return
		}
		rows, _ := cfg.Database.Query(c, `SELECT av_name, status, deleted, raw_json, updated_at FROM scan_results WHERE scan_id=$1 ORDER BY av_name`, scanID)
		defer rows.Close()
		var out []gin.H
		for rows.Next() {
			var avName, st string
			var deleted *bool
			var raw any
			var updated time.Time
			_ = rows.Scan(&avName, &st, &deleted, &raw, &updated)
			out = append(out, gin.H{"av": avName, "status": st, "deleted": deleted, "raw": raw, "updated_at": updated})
		}
		c.JSON(200, gin.H{"id": scanID, "status": status, "filename": filename, "sha256": sha, "results": out})
	})

	// Public: lookup by sha256 (anyone can see scans for a hash).
	r.GET("/hash/:sha", func(c *gin.Context) {
		sha := c.Param("sha")
		if !isSHA256Hex(sha) {
			c.String(400, "invalid sha256")
			return
		}
		rows, _ := cfg.Database.Query(c, `SELECT id, status, original_filename, created_at FROM scans WHERE sha256=$1 ORDER BY created_at DESC LIMIT 100`, sha)
		defer rows.Close()
		type item struct {
			ID       string
			Status   string
			Filename string
			Created  time.Time
		}
		var items []item
		for rows.Next() {
			var it item
			_ = rows.Scan(&it.ID, &it.Status, &it.Filename, &it.Created)
			items = append(items, it)
		}
		renderHTML(c, http.StatusOK, "hash.html", gin.H{"SHA256": sha, "Items": items})
	})

	r.GET("/api/hash/:sha", func(c *gin.Context) {
		sha := c.Param("sha")
		if !isSHA256Hex(sha) {
			c.JSON(400, gin.H{"error": "invalid sha256"})
			return
		}
		rows, _ := cfg.Database.Query(c, `SELECT id, status, original_filename, created_at FROM scans WHERE sha256=$1 ORDER BY created_at DESC LIMIT 100`, sha)
		defer rows.Close()
		var items []gin.H
		for rows.Next() {
			var id, status, filename string
			var created time.Time
			_ = rows.Scan(&id, &status, &filename, &created)
			items = append(items, gin.H{"id": id, "status": status, "filename": filename, "created_at": created})
		}
		c.JSON(200, gin.H{"sha256": sha, "scans": items})
	})

	if cfg.AdminUser != "" && cfg.AdminPass != "" {
		admin := r.Group("/admin", gin.BasicAuth(gin.Accounts{cfg.AdminUser: cfg.AdminPass}))
		admin.GET("/", func(c *gin.Context) {
			rows, _ := cfg.Database.Query(c, `
SELECT s.id, u.account_id, s.status, s.original_filename, s.created_at
FROM scans s
JOIN users u ON u.id=s.user_id
ORDER BY s.created_at DESC
LIMIT 50
`)
			defer rows.Close()
			type row struct {
				ID       string
				Account  string
				Status   string
				Filename string
				Created  time.Time
			}
			var items []row
			for rows.Next() {
				var it row
				_ = rows.Scan(&it.ID, &it.Account, &it.Status, &it.Filename, &it.Created)
				items = append(items, it)
			}
			renderHTML(c, http.StatusOK, "admin.html", gin.H{"Items": items})
		})
	}

	return r, nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, ch := range s {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		case ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return true
}

func setCookie(c *gin.Context, cfg RouterConfig, value string) {
	sameSite := http.SameSiteLaxMode
	if cfg.SameSiteStrict {
		sameSite = http.SameSiteStrictMode
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "monarch",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.SecureCookies,
		SameSite: sameSite,
		MaxAge:   60 * 60 * 24 * 30,
	})
}
