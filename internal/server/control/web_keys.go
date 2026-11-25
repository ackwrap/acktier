package control

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/types"
)

type adminKeyRow struct {
	ID, Label, Expires, State string
	Revocable                 bool
}

func adminKeyRows(keys []types.PreAuthKey, now time.Time) []adminKeyRow {
	out := make([]adminKeyRow, 0, len(keys))
	for _, key := range keys {
		row := adminKeyRow{ID: key.ID, Label: key.Label, Expires: key.ExpiresAt.UTC().Format(time.RFC3339)}
		switch {
		case key.Revoked:
			row.State = "已吊销"
		case !now.Before(key.ExpiresAt):
			row.State = "已过期"
		case !key.Reusable && key.UsedCount > 0:
			row.State = "已使用"
		default:
			row.State = "可用"
			row.Revocable = true
		}
		out = append(out, row)
	}
	return out
}

func (a *webAdmin) createKey(w http.ResponseWriter, r *http.Request, session webSession) {
	if !a.checkForm(w, r, session) {
		return
	}
	if a.server.ownerSetupPending() {
		a.problem(w, session, http.StatusConflict, "请先绑定所有者。")
		return
	}
	label := strings.TrimSpace(r.PostForm.Get("label"))
	if label == "" || utf8.RuneCountInString(label) > 64 {
		a.problem(w, session, http.StatusBadRequest, "请输入 1 到 64 个字符的申请码备注。")
		return
	}
	key, err := a.server.store.CreatePreAuthKey(label, false, false, nil, 24*time.Hour)
	if err != nil {
		log.Printf("[web-admin] create preauth key: %v", err)
		a.problem(w, session, http.StatusInternalServerError, "无法保存申请码，请检查中心的存储。")
		return
	}
	p := a.page(session)
	p.NewKey = key.Key
	renderAdmin(w, http.StatusCreated, p)
}

func (a *webAdmin) revokeKey(w http.ResponseWriter, r *http.Request, session webSession) {
	if !a.checkForm(w, r, session) {
		return
	}
	if a.server.ownerSetupPending() {
		a.problem(w, session, http.StatusConflict, "请先绑定所有者。")
		return
	}
	if err := a.server.store.RevokePreAuthKey(r.PathValue("id")); errors.Is(err, store.ErrNotFound) {
		a.problem(w, session, http.StatusNotFound, "找不到此申请码。")
		return
	} else if err != nil {
		log.Printf("[web-admin] revoke preauth key: %v", err)
		a.problem(w, session, http.StatusInternalServerError, "无法保存吊销记录，请检查中心的存储。")
		return
	}
	http.Redirect(w, r, adminURL+"?result=revoked-key", http.StatusSeeOther)
}
