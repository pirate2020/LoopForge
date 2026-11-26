package web

import (
	"os"
	"strings"
	"testing"
)

func TestLoginPageOffersIAM(t *testing.T) {
	page, err := os.ReadFile("login.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<h1>Agent 编排平台</h1>`,
		`src="/images/ft-logo.png"`,
		`使用 IAM 登录`,
		`class="button primary login-iam"`,
		`id="iamLogin"`,
		`id="otherLoginToggle"`,
		`其他登录方式`,
		`/login.js?v=20261126iam2`,
	} {
		if !strings.Contains(string(page), want) {
			t.Fatalf("login.html is missing %q", want)
		}
	}
	for _, unwanted := range []string{"casLogin", "loginSwitch", "switchMode", "iamDivider", "github.com/Tencent/LoopForge"} {
		if strings.Contains(string(page), unwanted) {
			t.Fatalf("login.html must not include %q", unwanted)
		}
	}

	script, err := os.ReadFile("login.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"fetch('/api/auth/iam')",
		"/api/auth/iam/start",
		"iam_error",
		"login_conflict",
		"account_linked",
		"link_disabled",
		"signup_disabled",
	} {
		if !strings.Contains(string(script), want) {
			t.Fatalf("login.js is missing %q", want)
		}
	}
	if strings.Contains(string(script), "/api/auth/cas") {
		t.Fatal("login.js must not call the removed CAS endpoints")
	}
}
