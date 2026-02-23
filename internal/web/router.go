package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
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

	type scanResultRow struct {
		AV        string
		Status    string
		Deleted   *bool
		Detection string
		Updated   time.Time
	}

	parseThreatName := func(msg string) string {
		msg = strings.TrimSpace(msg)
		if msg == "" {
			return ""
		}
		lines := strings.Split(msg, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "threat name") || strings.HasPrefix(lower, "name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
		return ""
	}

	detectionFromRaw := func(raw any) string {
		if raw == nil {
			return ""
		}
		b, _ := json.Marshal(raw)
		var parsed struct {
			ThreatName   string `json:"threat_name"`
			EventMessage string `json:"event_message"`
			ResultOut    string `json:"result_out"`
			ScriptOut    string `json:"script_out"`
			ScriptJSON   struct {
				DetectionName string `json:"detection_name"`
				Result        string `json:"result"`
			} `json:"script_json"`
		}
		if err := json.Unmarshal(b, &parsed); err != nil {
			return ""
		}
		det := strings.TrimSpace(parsed.ThreatName)
		if det == "" {
			det = parseThreatName(parsed.EventMessage)
		}
		if det == "" {
			det = strings.TrimSpace(parsed.ScriptJSON.DetectionName)
		}
		return det
	}

	type recentScan struct {
		ID        string
		Status    string
		Filename  string
		SHA256    string
		Detection string
		Created   string
	}

	loadRecentScans := func(c *gin.Context, accountID string) []recentScan {
		var recentScans []recentScan
		rows, err := cfg.Database.Query(c, `
SELECT s.id, s.status, s.original_filename, s.sha256, s.created_at,
       (SELECT sr.raw_json FROM scan_results sr WHERE sr.scan_id=s.id AND sr.status='malware' ORDER BY sr.updated_at DESC LIMIT 1) AS raw_json
FROM scans s
JOIN users u ON u.id = s.user_id
WHERE u.account_id = $1
ORDER BY s.created_at DESC LIMIT 20`, accountID)
		if err != nil {
			return recentScans
		}
		defer rows.Close()
		for rows.Next() {
			var it recentScan
			var created time.Time
			var raw any
			_ = rows.Scan(&it.ID, &it.Status, &it.Filename, &it.SHA256, &created, &raw)
			it.Created = created.Format("Jan 2, 2006 15:04")
			it.Detection = detectionFromRaw(raw)
			recentScans = append(recentScans, it)
		}
		return recentScans
	}

	loadScanSummary := func(c *gin.Context, scanID string) (string, string, string, int64, string, string, string, string, time.Time, bool) {
		var status, filename, sha, md5sum, sha1sum, crc32sum string
		var size int64
		var created time.Time
		var ssdeep *string
		err := cfg.Database.QueryRow(c, `
SELECT status, original_filename, sha256, file_size, md5, sha1, crc32, ssdeep, created_at
FROM scans WHERE id=$1`, scanID).Scan(&status, &filename, &sha, &size, &md5sum, &sha1sum, &crc32sum, &ssdeep, &created)
		if err != nil {
			return "", "", "", 0, "", "", "", "", time.Time{}, false
		}
		ss := ""
		if ssdeep != nil {
			ss = *ssdeep
		}
		return status, filename, sha, size, md5sum, sha1sum, crc32sum, ss, created, true
	}

	loadScanResults := func(c *gin.Context, scanID string) []scanResultRow {
		rows, _ := cfg.Database.Query(c, `SELECT av_name, status, deleted, raw_json, updated_at FROM scan_results WHERE scan_id=$1 ORDER BY av_name`, scanID)
		if rows == nil {
			return nil
		}
		defer rows.Close()
		var results []scanResultRow
		for rows.Next() {
			var r scanResultRow
			var raw any
			_ = rows.Scan(&r.AV, &r.Status, &r.Deleted, &raw, &r.Updated)
			r.Detection = detectionFromRaw(raw)
			results = append(results, r)
		}
		return results
	}

	clearCookie := func(c *gin.Context) {
		sameSite := http.SameSiteLaxMode
		if cfg.SameSiteStrict {
			sameSite = http.SameSiteStrictMode
		}
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "monarch",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   cfg.SecureCookies,
			SameSite: sameSite,
			MaxAge:   -1,
		})
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
	scanIPLimiter := ratelimit.NewWindowCounter(cfg.CaptchaWindow, cfg.CaptchaThresh)
	scanAccountLimiter := ratelimit.NewWindowCounter(cfg.CaptchaWindow, cfg.CaptchaThresh)

	setUser := func(c *gin.Context) {
		cookie, err := c.Cookie("monarch")
		if err == nil {
			if accountID, ok := auth.VerifyCookie(cfg.CookieSecret, cookie); ok {
				var banned bool
				err := cfg.Database.QueryRow(c, `SELECT is_banned FROM users WHERE account_id=$1`, accountID).Scan(&banned)
				if err != nil {
					clearCookie(c)
					c.Next()
					return
				}
				if banned {
					clearCookie(c)
					c.Next()
					return
				}
				c.Set("account_id", accountID)
			}
		}
		c.Next()
	}
	r.Use(setUser)

	r.GET("/", func(c *gin.Context) {
		accountID, _ := c.Get("account_id")
		var chartData template.JS
		var recentScans []recentScan
		if accountID != nil {
			recentScans = loadRecentScans(c, accountID.(string))

			var labels []string
			var scanCounts []int64
			var userCounts []int64
			scanRows, _ := cfg.Database.Query(c, `
SELECT d::date AS day, COALESCE(COUNT(s.id), 0) AS count
FROM generate_series(date_trunc('day', now()) - interval '2 days', date_trunc('day', now()), interval '1 day') d
LEFT JOIN scans s
  ON s.created_at >= d AND s.created_at < d + interval '1 day'
GROUP BY day
ORDER BY day
`)
			if scanRows != nil {
				for scanRows.Next() {
					var day time.Time
					var n int64
					_ = scanRows.Scan(&day, &n)
					labels = append(labels, day.Format("Jan 02"))
					scanCounts = append(scanCounts, n)
				}
				scanRows.Close()
			}

			userRows, _ := cfg.Database.Query(c, `
SELECT d::date AS day, COALESCE(COUNT(u.id), 0) AS count
FROM generate_series(date_trunc('day', now()) - interval '2 days', date_trunc('day', now()), interval '1 day') d
LEFT JOIN users u
  ON u.created_at >= d AND u.created_at < d + interval '1 day'
GROUP BY day
ORDER BY day
`)
			if userRows != nil {
				for userRows.Next() {
					var day time.Time
					var n int64
					_ = userRows.Scan(&day, &n)
					userCounts = append(userCounts, n)
				}
				userRows.Close()
			}

			statusCounts := map[string]int64{}
			stRows, _ := cfg.Database.Query(c, `SELECT status, COUNT(*) FROM scans WHERE created_at >= now() - interval '30 days' GROUP BY status`)
			if stRows != nil {
				for stRows.Next() {
					var st string
					var n int64
					_ = stRows.Scan(&st, &n)
					statusCounts[st] = n
				}
				stRows.Close()
			}

			chart := map[string]any{
				"labels":       labels,
				"scanCounts":   scanCounts,
				"userCounts":   userCounts,
				"statusLabels": []string{"clean", "malware", "error"},
				"statusCounts": []int64{statusCounts["clean"], statusCounts["malware"], statusCounts["error"]},
			}
			if b, err := json.Marshal(chart); err == nil {
				chartData = template.JS(b)
			}
		}
		renderHTML(c, http.StatusOK, "index.html", gin.H{
			"AccountID":      accountID,
			"RequireCaptcha": cfg.Scanner.CaptchaEnabled(),
			"RecentScans":    recentScans,
			"ChartData":      chartData,
		})
	})

	r.GET("/partials/recent-scans", func(c *gin.Context) {
		accountID, ok := c.Get("account_id")
		if !ok {
			c.Status(http.StatusNoContent)
			return
		}
		recentScans := loadRecentScans(c, accountID.(string))
		renderHTML(c, http.StatusOK, "partials_recent_scans.html", gin.H{
			"RecentScans": recentScans,
		})
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
		var banned bool
		err := cfg.Database.QueryRow(c, `SELECT id, password_hash, is_banned FROM users WHERE account_id=$1`, accountID).Scan(&userID, &stored, &banned)
		if err != nil {
			renderHTML(c, http.StatusBadRequest, "login.html", gin.H{"Error": "invalid credentials", "RequireCaptcha": cfg.RequireCaptcha})
			return
		}
		if banned {
			renderHTML(c, http.StatusForbidden, "login.html", gin.H{"Error": "account disabled", "RequireCaptcha": cfg.RequireCaptcha})
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
		clearCookie(c)
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
		if _, over := scanIPLimiter.Increment("scan-ip:"+ip, time.Now()); over {
			renderHTML(c, http.StatusTooManyRequests, "index.html", gin.H{"Error": "rate limit exceeded", "AccountID": accountID})
			return
		}
		if accountID != nil {
			if _, over := scanAccountLimiter.Increment("scan-account:"+accountID.(string), time.Now()); over {
				renderHTML(c, http.StatusTooManyRequests, "index.html", gin.H{"Error": "rate limit exceeded", "AccountID": accountID})
				return
			}
		}
		if cfg.Scanner.ShouldRequireCaptcha(ip, time.Now()) {
			id := c.PostForm("captcha_id")
			sol := c.PostForm("captcha_solution")
			if !captcha.VerifyString(id, sol) {
				renderHTML(c, http.StatusBadRequest, "index.html", gin.H{"Error": "captcha failed", "AccountID": accountID})
				return
			}
		}

		var userID int64
		var banned bool
		err := cfg.Database.QueryRow(c, `SELECT id, is_banned FROM users WHERE account_id=$1`, accountID.(string)).Scan(&userID, &banned)
		if err != nil {
			renderHTML(c, http.StatusBadRequest, "index.html", gin.H{"Error": "invalid user", "AccountID": accountID})
			return
		}
		if banned {
			clearCookie(c)
			renderHTML(c, http.StatusForbidden, "index.html", gin.H{"Error": "account disabled", "AccountID": nil})
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
		status, filename, sha, size, md5sum, sha1sum, crc32sum, ssdeep, created, ok := loadScanSummary(c, scanID)
		if !ok {
			c.String(404, "not found")
			return
		}
		results := loadScanResults(c, scanID)
		detected := 0
		for _, r := range results {
			if r.Status == "malware" {
				detected++
			}
		}
		terminal := status == "clean" || status == "malware" || status == "error"

		renderHTML(c, http.StatusOK, "scan.html", gin.H{
			"ScanID":        scanID,
			"Status":        status,
			"Filename":      filename,
			"SHA256":        sha,
			"MD5":           md5sum,
			"SHA1":          sha1sum,
			"CRC32":         crc32sum,
			"SSDEEP":        ssdeep,
			"FileSize":      size,
			"CreatedAt":     created,
			"DetectedCount": detected,
			"EngineCount":   len(results),
			"Results":       results,
			"IsTerminal":    terminal,
		})
	})

	r.GET("/partials/scan-status/:id", func(c *gin.Context) {
		scanID := c.Param("id")
		status, filename, sha, _, _, _, _, _, _, ok := loadScanSummary(c, scanID)
		if !ok {
			c.Status(http.StatusNotFound)
			return
		}
		terminal := status == "clean" || status == "malware" || status == "error"
		renderHTML(c, http.StatusOK, "partials_scan_status.html", gin.H{
			"ScanID":     scanID,
			"Status":     status,
			"Filename":   filename,
			"SHA256":     sha,
			"IsTerminal": terminal,
		})
	})

	r.GET("/partials/scan-banner/:id", func(c *gin.Context) {
		scanID := c.Param("id")
		status, _, _, _, _, _, _, _, _, ok := loadScanSummary(c, scanID)
		if !ok {
			c.Status(http.StatusNotFound)
			return
		}
		terminal := status == "clean" || status == "malware" || status == "error"
		renderHTML(c, http.StatusOK, "partials_scan_banner.html", gin.H{
			"ScanID":     scanID,
			"IsTerminal": terminal,
		})
	})

	r.GET("/partials/scan-results/:id", func(c *gin.Context) {
		scanID := c.Param("id")
		results := loadScanResults(c, scanID)
		status, _, _, _, _, _, _, _, _, ok := loadScanSummary(c, scanID)
		if !ok {
			c.Status(http.StatusNotFound)
			return
		}
		terminal := status == "clean" || status == "malware" || status == "error"
		renderHTML(c, http.StatusOK, "partials_scan_results.html", gin.H{
			"ScanID":     scanID,
			"Results":    results,
			"IsTerminal": terminal,
		})
	})

	// Public: scan JSON is visible to anyone.
	r.GET("/api/scan/:id", func(c *gin.Context) {
		scanID := c.Param("id")
		var status, filename, sha, md5sum, sha1sum, crc32sum string
		var size int64
		var created time.Time
		var ssdeep *string
		err := cfg.Database.QueryRow(c, `SELECT status, original_filename, sha256, file_size, md5, sha1, crc32, ssdeep, created_at FROM scans WHERE id=$1`, scanID).Scan(&status, &filename, &sha, &size, &md5sum, &sha1sum, &crc32sum, &ssdeep, &created)
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
			out = append(out, gin.H{"av": avName, "status": st, "deleted": deleted, "detection": detectionFromRaw(raw), "raw": raw, "updated_at": updated})
		}
		ss := ""
		if ssdeep != nil {
			ss = *ssdeep
		}
		c.JSON(200, gin.H{"id": scanID, "status": status, "filename": filename, "sha256": sha, "md5": md5sum, "sha1": sha1sum, "crc32": crc32sum, "ssdeep": ss, "file_size": size, "created_at": created, "results": out})
	})

	if cfg.AdminUser != "" && cfg.AdminPass != "" {
		admin := r.Group("/admin", gin.BasicAuth(gin.Accounts{cfg.AdminUser: cfg.AdminPass}))
		admin.POST("/user/:account/ban", func(c *gin.Context) {
			acct := c.Param("account")
			reason := strings.TrimSpace(c.PostForm("reason"))
			if acct == "" {
				c.Redirect(http.StatusSeeOther, "/admin/")
				return
			}
			_, _ = cfg.Database.Exec(c, `UPDATE users SET is_banned=TRUE, banned_at=now(), ban_reason=$2 WHERE account_id=$1`, acct, reason)
			clearCookie(c)
			c.Redirect(http.StatusSeeOther, "/admin/")
		})

		admin.POST("/user/:account/unban", func(c *gin.Context) {
			acct := c.Param("account")
			if acct == "" {
				c.Redirect(http.StatusSeeOther, "/admin/")
				return
			}
			_, _ = cfg.Database.Exec(c, `UPDATE users SET is_banned=FALSE, banned_at=NULL, ban_reason=NULL WHERE account_id=$1`, acct)
			c.Redirect(http.StatusSeeOther, "/admin/")
		})

		admin.POST("/user/:account/credits", func(c *gin.Context) {
			acct := c.Param("account")
			deltaStr := strings.TrimSpace(c.PostForm("delta"))
			if acct == "" || deltaStr == "" {
				c.Redirect(http.StatusSeeOther, "/admin/")
				return
			}
			delta, err := strconv.ParseInt(deltaStr, 10, 64)
			if err != nil {
				c.Redirect(http.StatusSeeOther, "/admin/")
				return
			}
			_, _ = cfg.Database.Exec(c, `UPDATE users SET credits_balance = GREATEST(0, credits_balance + $2) WHERE account_id=$1`, acct, delta)
			c.Redirect(http.StatusSeeOther, "/admin/")
		})

		admin.GET("/", func(c *gin.Context) {
			type stat struct {
				Label string
				Value string
			}
			var userCount int64
			_ = cfg.Database.QueryRow(c, `SELECT COUNT(*) FROM users`).Scan(&userCount)
			var scanCountAll int64
			_ = cfg.Database.QueryRow(c, `SELECT COUNT(*) FROM scans`).Scan(&scanCountAll)
			var scanCount30d int64
			_ = cfg.Database.QueryRow(c, `SELECT COUNT(*) FROM scans WHERE created_at >= now() - interval '30 days'`).Scan(&scanCount30d)

			statusCounts := map[string]int64{}
			rows, _ := cfg.Database.Query(c, `SELECT status, COUNT(*) FROM scans WHERE created_at >= now() - interval '30 days' GROUP BY status`)
			if rows != nil {
				for rows.Next() {
					var st string
					var n int64
					_ = rows.Scan(&st, &n)
					statusCounts[st] = n
				}
				rows.Close()
			}

			type dayCount struct {
				Day   time.Time
				Count int64
			}
			var series []dayCount
			var maxDaily int64
			days, _ := cfg.Database.Query(c, `
SELECT d::date AS day, COALESCE(COUNT(s.id), 0) AS count
FROM generate_series(date_trunc('day', now()) - interval '29 days', date_trunc('day', now()), interval '1 day') d
LEFT JOIN scans s
  ON s.created_at >= d AND s.created_at < d + interval '1 day'
GROUP BY day
ORDER BY day
`)
			if days != nil {
				for days.Next() {
					var day time.Time
					var n int64
					_ = days.Scan(&day, &n)
					if n > maxDaily {
						maxDaily = n
					}
					series = append(series, dayCount{Day: day, Count: n})
				}
				days.Close()
			}

			type userRow struct {
				Account        string
				Created        time.Time
				Banned         bool
				CreditsBalance int64
				Scans30d       int64
				LastScan       *time.Time
			}
			var users []userRow
			top, _ := cfg.Database.Query(c, `
SELECT u.account_id, u.created_at, u.is_banned, u.credits_balance,
       COALESCE(COUNT(s.id), 0) AS scans_30d,
       MAX(s.created_at) AS last_scan
FROM users u
LEFT JOIN scans s
  ON s.user_id = u.id
 AND s.created_at >= now() - interval '30 days'
GROUP BY u.id
ORDER BY scans_30d DESC, u.created_at DESC
LIMIT 20
`)
			if top != nil {
				for top.Next() {
					var it userRow
					var last *time.Time
					_ = top.Scan(&it.Account, &it.Created, &it.Banned, &it.CreditsBalance, &it.Scans30d, &last)
					it.LastScan = last
					users = append(users, it)
				}
				top.Close()
			}

			stats := []stat{
				{Label: "Users", Value: fmt.Sprintf("%d", userCount)},
				{Label: "Scans (all time)", Value: fmt.Sprintf("%d", scanCountAll)},
				{Label: "Scans (last 30d)", Value: fmt.Sprintf("%d", scanCount30d)},
				{Label: "Clean (30d)", Value: fmt.Sprintf("%d", statusCounts["clean"])},
				{Label: "Malware (30d)", Value: fmt.Sprintf("%d", statusCounts["malware"])},
				{Label: "Error (30d)", Value: fmt.Sprintf("%d", statusCounts["error"])},
			}

			scanRows, _ := cfg.Database.Query(c, `
SELECT s.id, u.account_id, s.status, s.original_filename, s.created_at
FROM scans s
JOIN users u ON u.id=s.user_id
ORDER BY s.created_at DESC
LIMIT 50
`)
			type row struct {
				ID       string
				Account  string
				Status   string
				Filename string
				Created  time.Time
			}
			var items []row
			if scanRows != nil {
				defer scanRows.Close()
				for scanRows.Next() {
					var it row
					_ = scanRows.Scan(&it.ID, &it.Account, &it.Status, &it.Filename, &it.Created)
					items = append(items, it)
				}
			}
			renderHTML(c, http.StatusOK, "admin.html", gin.H{
				"Items":        items,
				"Stats":        stats,
				"Series":       series,
				"SeriesMax":    maxDaily,
				"TopUsers":     users,
				"StatusCounts": statusCounts,
			})
		})
	}

	return r, nil
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
