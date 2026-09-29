// Package samples 为审计工具自检样例：包含多处**故意构造**的安全缺陷。
// 请勿在生产环境使用；仅用于验证规则引擎是否正常工作。
package samples

import (
	"archive/zip"
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"unsafe"
)

// ---- 1. 硬编码凭据（SEC-KEY-001 / SEC-KEY-002 / SEC-KEY-003）----
const (
	dbPassword   = "P@ssw0rd!2024"
	apiKey       = "sk-live-9f8a7b6c5d4e3f2a1b0c9d8e"
	awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
)

// ---- 2. SQL 注入（INJ-SQL-001）----
func QueryUser(db *sql.DB, name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT id, name FROM users WHERE name = '%s'", name)
	return db.Query(query)
}

// ---- 3. 命令注入（INJ-CMD-001）----
func PingHost(host string) ([]byte, error) {
	return exec.Command("sh", "-c", "ping -c 1 "+host).Output()
}

// ---- 4. 路径遍历（TRAV-PATH-001）----
func ReadUserFile(base, fileName string) ([]byte, error) {
	return os.ReadFile(base + fileName)
}

// ---- 5. 越界风险（OOB-INDEX-001 / OOB-SLICE-001）----
func LastTwo(buf []byte, n int) (byte, []byte, error) {
	prev := buf[n-1]      // 索引含算术运算，n 为 0 时越界 panic
	tail := buf[n : n+2]  // 切片上界 n+2 可能超过 len(buf)
	return prev, tail, nil
}

// ---- 6. 弱加密 / 弱随机（CRY-WEAK-001 / CRY-RAND-001）----
func WeakHash(data []byte) []byte {
	sum := md5.Sum(data)
	return sum[:]
}

func SessionID() int64 {
	return rand.Int63()
}

// ---- 7. TLS 校验关闭（CRY-TLS-001）----
func InsecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// ---- 8. 敏感信息写入日志（SEC-LOG-001）----
func Login(name, password string) {
	log.Printf("user=%s password=%s", name, password)
}

// ---- 9. SSRF（SSRF-REQ-001）----
func Fetch(input string) (*http.Response, error) {
	return http.Get(input)
}

// ---- 10. unsafe 使用（OOB-UNSAFE-001）----
func RawBytes(p *byte, n int) []byte {
	return unsafe.Slice(p, n)
}

// ---- 11. 文件权限过宽（TRAV-PERM-001）+ 固定临时文件（TRAV-TEMP-001）----
func WriteConfig(data []byte) error {
	return os.WriteFile("/tmp/app-config.json", data, 0777)
}

// ---- 12. HTTP 服务未设超时（QUA-HTTP-001）----
func StartServer() error {
	srv := &http.Server{Addr: ":8080"}
	return srv.ListenAndServe()
}

// ---- 13. 错误被静默忽略（QUA-ERR-001）----
func Cleanup(path string) {
	_, _ = os.ReadFile(path)
}

// ---- 14. 遗留安全 TODO（QUA-TODO-001）----
// TODO: missing validation on user input before query
func HandleInput(v string) string { return v }

// ---- 15. Zip Slip：用压缩包条目名拼接落盘路径（TRAV-ZIP-001）----
func UnzipTo(dest string, r io.ReaderAt, size int64) error {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		target := filepath.Join(dest, f.Name) // 条目名可含 ../../，写到目标目录之外
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		defer out.Close()
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		if _, err := io.CopyN(out, rc, 1<<20); err != nil {
			return err
		}
	}
	return nil
}
