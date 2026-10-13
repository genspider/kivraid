package i18n

// French: application shell (top bar, account menu, side menus).
func init() {
	Register("fr", map[string]string{
		"Main":             "Principal",
		"Administration":   "Administration",
		"Account settings": "Paramètres du compte",
		"Accounts":         "Comptes",
		"Identity sources": "Sources d'identité",
		"Diagnostics":      "Diagnostic",

		// Admin tables.
		"User":                  "Utilisateur",
		"Last sign-in":          "Dernière connexion",
		"Never":                 "Jamais",
		"2FA":                   "2FA",
		"Group":                 "Groupe",
		"Application":           "Application",
		"Address":               "Adresse",
		"Type":                  "Type",
		"Two-factor & passkeys": "Double authentification et clés d'accès",
		"A second step at sign-in protects your account if your password leaks.":           "Une seconde étape à la connexion protège votre compte si votre mot de passe fuite.",
		"Your password is managed by the directory or identity provider you sign in with.": "Votre mot de passe est géré par l'annuaire ou le fournisseur d'identité avec lequel vous vous connectez.",
	})
}
