package scan

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"Monarch/internal/av"
	"Monarch/internal/ratelimit"
	"Monarch/internal/winrmexec"

	"github.com/glaslos/ssdeep"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ServiceConfig struct {
	StorageDir     string
	MaxUploadBytes int64
	ScanWait       time.Duration
	WorkerCount    int

	WinRMUser     string
	WinRMPass     string
	WinRMPort     int
	WinRMUseHTTPS bool
	WinRMInsecure bool

	AVTargets []av.Target
	Database  *pgxpool.Pool

	RequireCaptcha bool
	CaptchaThresh  int
	CaptchaWindow  time.Duration

	CaptchaSiteKey string
	CaptchaSecret  string
}

type Service struct {
	cfg    ServiceConfig
	queue  chan job
	closed chan struct{}
	wg     sync.WaitGroup
	runner *winrmexec.Runner
	burst  *ratelimit.WindowCounter
}

type job struct {
	scanID    uuid.UUID
	userID    int64
	sha256    string
	localPath string
}

func NewService(cfg ServiceConfig) *Service {
	os.MkdirAll(cfg.StorageDir, 0o700)
	_ = purgeStorageDir(cfg.StorageDir)

	s := &Service{
		cfg:    cfg,
		queue:  make(chan job, 256),
		closed: make(chan struct{}),
		runner: winrmexec.NewRunner(winrmexec.Config{
			User:     cfg.WinRMUser,
			Pass:     cfg.WinRMPass,
			Port:     cfg.WinRMPort,
			UseHTTPS: cfg.WinRMUseHTTPS,
			Insecure: cfg.WinRMInsecure,
		}),
		burst: ratelimit.NewWindowCounter(cfg.CaptchaWindow, cfg.CaptchaThresh),
	}

	for i := 0; i < cfg.WorkerCount; i++ {
		s.wg.Add(1)
		go s.worker()
	}

	return s
}

func (s *Service) Close() {
	close(s.closed)
	s.wg.Wait()
}

func (s *Service) CaptchaEnabled() bool {
	return s.cfg.RequireCaptcha
}

func (s *Service) ShouldRequireCaptcha(ip string, now time.Time) bool {
	_, over := s.burst.Increment(ip, now)
	return s.cfg.RequireCaptcha && over
}

func (s *Service) EnqueueScan(ctx context.Context, userID int64, fileHeader *multipart.FileHeader) (uuid.UUID, error) {
	if fileHeader == nil {
		return uuid.Nil, errors.New("missing file")
	}
	if fileHeader.Size > s.cfg.MaxUploadBytes {
		return uuid.Nil, fmt.Errorf("file too large (%d > %d)", fileHeader.Size, s.cfg.MaxUploadBytes)
	}

	scanID := uuid.New()
	name := sanitizeFilename(fileHeader.Filename)
	localDir := filepath.Join(s.cfg.StorageDir, scanID.String())
	if err := os.MkdirAll(localDir, 0o700); err != nil {
		return uuid.Nil, err
	}
	tmpPath := filepath.Join(localDir, "upload.tmp")

	file, err := fileHeader.Open()
	if err != nil {
		return uuid.Nil, err
	}
	defer file.Close()

	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return uuid.Nil, err
	}
	defer out.Close()

	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()
	crch := crc32.NewIEEE()
	writer := io.MultiWriter(out, md5h, sha1h, sha256h, crch)
	counting := &countWriter{w: writer}
	limited := io.LimitReader(file, s.cfg.MaxUploadBytes+1)
	tee := io.TeeReader(limited, counting)
	var ssdeepHash *string
	if fuzzy, err := ssdeep.FuzzyReader(tee); err == nil {
		ssdeepHash = &fuzzy
	}
	n := counting.n
	if n > s.cfg.MaxUploadBytes {
		_ = os.Remove(tmpPath)
		return uuid.Nil, fmt.Errorf("file too large (%d > %d)", n, s.cfg.MaxUploadBytes)
	}
	sha := hex.EncodeToString(sha256h.Sum(nil))
	md5sum := hex.EncodeToString(md5h.Sum(nil))
	sha1sum := hex.EncodeToString(sha1h.Sum(nil))
	crc := fmt.Sprintf("%08x", crch.Sum32())
	localPath := filepath.Join(localDir, sha)
	if err := os.Rename(tmpPath, localPath); err != nil {
		return uuid.Nil, err
	}

	_, err = s.cfg.Database.Exec(ctx, `INSERT INTO scans (id, user_id, original_filename, file_size, md5, sha1, sha256, crc32, ssdeep, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		scanID, userID, name, n, md5sum, sha1sum, sha, crc, ssdeepHash, "queued")
	if err != nil {
		return uuid.Nil, err
	}
	for _, t := range s.cfg.AVTargets {
		_, _ = s.cfg.Database.Exec(ctx, `INSERT INTO scan_results (id, scan_id, av_name, status) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
			uuid.New(), scanID, t.Antivirus, "queued")
	}

	select {
	case s.queue <- job{scanID: scanID, userID: userID, sha256: sha, localPath: localPath}:
		return scanID, nil
	case <-ctx.Done():
		return uuid.Nil, ctx.Err()
	}
}

func (s *Service) worker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.closed:
			return
		case j := <-s.queue:
			s.runJob(context.Background(), j)
		}
	}
}

func (s *Service) runJob(ctx context.Context, j job) {
	defer removeScanFiles(j.localPath)

	_, _ = s.cfg.Database.Exec(ctx, `UPDATE scans SET status=$2, updated_at=now() WHERE id=$1`, j.scanID, "running")

	fileBytes, err := os.ReadFile(j.localPath)
	if err != nil {
		s.fail(ctx, j.scanID, "read file", err)
		return
	}
	overall := "clean"
	type targetResult struct {
		target av.Target
		res    winrmexec.ScanResult
		err    error
	}
	results := make([]targetResult, len(s.cfg.AVTargets))
	var twg sync.WaitGroup
	for i, target := range s.cfg.AVTargets {
		_, _ = s.cfg.Database.Exec(ctx, `UPDATE scan_results SET status='scanning', updated_at=now() WHERE scan_id=$1 AND av_name=$2`, j.scanID, target.Antivirus)
		twg.Add(1)
		go func(i int, target av.Target) {
			defer twg.Done()
			res, err := s.runner.RunScan(ctx, winrmexec.ScanRequest{
				TargetIP:      target.IP,
				AVName:        target.Antivirus,
				ScriptPath:    target.ScriptLocation,
				RemoteWorkDir: target.RemoteWorkDir,
				ScanID:        j.scanID.String(),
				SHA256:        j.sha256,
				Bytes:         fileBytes,
				Wait:          s.cfg.ScanWait,
			})
			results[i] = targetResult{target: target, res: res, err: err}
		}(i, target)
	}
	twg.Wait()

	for _, r := range results {
		status := "clean"
		if r.err != nil {
			status = "error"
		} else if r.res.Deleted {
			status = "malware"
			overall = "malware"
		}
		raw, _ := json.Marshal(r.res)
		_, _ = s.cfg.Database.Exec(ctx, `UPDATE scan_results SET status=$3, deleted=$4, raw_json=$5::jsonb, updated_at=now() WHERE scan_id=$1 AND av_name=$2`,
			j.scanID, r.target.Antivirus, status, r.res.Deleted, string(raw))
	}

	_, _ = s.cfg.Database.Exec(ctx, `UPDATE scans SET status=$2, updated_at=now() WHERE id=$1`, j.scanID, overall)
}

func (s *Service) fail(ctx context.Context, scanID uuid.UUID, stage string, err error) {
	_, _ = s.cfg.Database.Exec(ctx, `UPDATE scans SET status=$2, updated_at=now() WHERE id=$1`, scanID, "error")
	_, _ = s.cfg.Database.Exec(ctx, `UPDATE scan_results SET status=$2, updated_at=now(), raw_json=jsonb_build_object('error', $3::text, 'stage', $4::text) WHERE scan_id=$1`,
		scanID, "error", err.Error(), stage)
}

func sanitizeFilename(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.TrimSpace(name)
	if name == "" {
		return "file.bin"
	}
	return name
}

type countWriter struct {
	n int64
	w io.Writer
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func removeScanFiles(localPath string) {
	if localPath == "" {
		return
	}
	localDir := filepath.Dir(localPath)
	_ = os.Remove(localPath)
	_ = os.RemoveAll(localDir)
}

func purgeStorageDir(storageDir string) error {
	if storageDir == "" {
		return nil
	}
	entries, err := os.ReadDir(storageDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		_ = os.RemoveAll(filepath.Join(storageDir, entry.Name()))
	}
	return nil
}
