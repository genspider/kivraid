package i18n

// 简体中文：应用外壳（顶栏、账户菜单、侧边菜单）。
func init() {
	Register("zh", map[string]string{
		"Main":             "主导航",
		"Administration":   "管理",
		"Account settings": "账户设置",
		"Accounts":         "账户",
		"Identity sources": "身份来源",
		"Diagnostics":      "诊断",

		// 管理表格。
		"User":                  "用户",
		"Last sign-in":          "上次登录",
		"Never":                 "从未",
		"2FA":                   "双因素",
		"Group":                 "组",
		"Application":           "应用",
		"Address":               "地址",
		"Type":                  "类型",
		"Two-factor & passkeys": "双因素与通行密钥",
		"A second step at sign-in protects your account if your password leaks.":           "登录时的第二步验证可在密码泄露时保护你的账户。",
		"Your password is managed by the directory or identity provider you sign in with.": "你的密码由登录所用的目录或身份提供方管理。",
	})
}
