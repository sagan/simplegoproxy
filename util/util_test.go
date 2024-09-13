package util

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestMatchUrlPattern(t *testing.T) {
	type args struct {
		comment       string
		pattern       string
		positive_urls []string
		negative_urls []string
	}
	tests := []args{
		{
			comment:       "Matches any http(s) URL",
			pattern:       "*://*/*",
			positive_urls: []string{"https://www.google.com/", "http://example.com:3000/abc"},
			negative_urls: []string{"file:///root/foo.txt", "rclone://remote/path"},
		},
		{
			comment:       "Matches any URL using the https scheme",
			pattern:       "https://*/*",
			positive_urls: []string{"https://www.google.com/"},
			negative_urls: []string{"http://www.google.com/"},
		},
		{
			comment:       "Matches any URL using the https scheme, on any host, with a path that starts with foo",
			pattern:       "https://*/foo*",
			positive_urls: []string{"https://example.com/foo/bar.html", "https://www.google.com/foo"},
			negative_urls: []string{"http://example.com/foo/bar.html", "https://example.com/bar"},
		},
		{
			comment: "Matches any URL using the https scheme, on a google.com host, with a path that starts with foo and ends with bar",
			pattern: "https://*.google.com/foo*bar",
			positive_urls: []string{
				"https://www.google.com/foo/baz/bar",
				"https://docs.google.com/foobar",
				"https://sub.www.google.com/foo/baz/bar",
			},
			negative_urls: []string{"https://google.com/foo/baz/bar"},
		},
		{
			comment:       "Matches any local file whose path starts with foo",
			pattern:       "file:///foo*",
			positive_urls: []string{"file:///foo/bar.html", "file:///foo", "file:///foobar"},
			negative_urls: []string{"http:///foo/bar.html", "file:///bar"},
		},
		{
			comment:       "Matches any URL that uses the http scheme and is on the host 127.0.0.1.",
			pattern:       "http://127.0.0.1/*",
			positive_urls: []string{"http://127.0.0.1/", "http://127.0.0.1/foo/bar.html"},
			negative_urls: []string{"https://127.0.0.1/", "http://www.google.com/"},
		},
		{
			comment:       "Matches any protocol URL with exact host and root path",
			pattern:       "*://mail.google.com/",
			positive_urls: []string{"http://mail.google.com", "http://mail.google.com/"},
			negative_urls: []string{"http://www.google.com/", "http://mail.google.com/?a",
				"http://mail.google.com/foo", "https://mail.google.com/foo"},
		},
		{
			comment: "Matches any URL that starts with http://mail.google.com or https://mail.google.com",
			pattern: "*://mail.google.com/*",
			positive_urls: []string{"http://mail.google.com", "http://mail.google.com/",
				"http://mail.google.com/foo", "https://mail.google.com/foo"},
			negative_urls: []string{"http://www.google.com/"},
		},
		{
			comment:       "Matches any URL that has schema://host of rclone://local",
			pattern:       "rclone://local/*",
			positive_urls: []string{"rclone://local", "rclone://local/", "rclone://local/path"},
			negative_urls: []string{"http://local/path", "rclone://remote/path"},
		},
		{
			comment:       "Match prefix unix domain socket url",
			pattern:       "unix:///path/*",
			positive_urls: []string{"unix:///path/socket:/path"},
			negative_urls: []string{"unix:///path2/socket:/path"},
		},
		{
			comment:       "Match exact unix domain socket url",
			pattern:       "unix:///path/socket:*",
			positive_urls: []string{"unix:///path/socket:/"},
			negative_urls: []string{"unix:///path/socket2:/"},
		},
	}
	for _, test := range tests {
		matcher := CreateUrlPatternMatcher(test.pattern)
		for _, url := range test.positive_urls {
			if !matcher(url) {
				t.Errorf("test=%s, pattern=%s, url=%s, result=false, want=true", test.comment, test.pattern, url)
			}
		}
		for _, url := range test.negative_urls {
			if matcher(url) {
				t.Errorf("pattern=%s, url=%s, result=true, want=false", test.pattern, url)
			}
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	pass := "abc"
	encryptCipher, err := GetCipher(pass, "")
	if err != nil {
		t.Fatalf("Failed to get encrypt cipher: %v", err)
	}
	str := "In God We Trust"
	cipherstring := EncryptToString(encryptCipher, []byte(str))

	decryptCipher, err := GetCipher(pass, "")
	if err != nil {
		t.Fatalf("Failed to get decrypt cipher: %v", err)
	}
	decryptedData, err := DecryptString(decryptCipher, cipherstring)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if str != string(decryptedData) {
		t.Fatalf("Decrypted data not correct")
	}
}

// Encryption / Decryption schema combined shared password & public key exchange.
// 0. alice and bob share a pass (used as pre shared key).
// 1. alice => bob : send alice's public key and a salt.
// 2. bob derives cipher key from:
// pass, salt, ECDH key exchange result of bob's private key + alice's public key.
// encrypt data use AES-256-GCM.
// 3. bob => alice : send bob's public key and encrypted data.
// 4. alice derives cipher key using similar way, decrypt data.
func TestPublickeyEncryptDecrypt(t *testing.T) {
	pass := "abc"
	salt := "s"
	curve := ecdh.X25519()
	alicekey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ecdh private key: %v", err)
	}
	bobkey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ecdh private key: %v", err)
	}
	alicepub := alicekey.PublicKey()
	bobpub := bobkey.PublicKey()

	bobCipher, err := GetPublickeyCipher(pass, salt, bobkey, alicepub)
	if err != nil {
		t.Fatalf("Failed to get encrypt cipher: %v", err)
	}
	plainstring := "In God We Trust"
	cipherstring := EncryptToString(bobCipher, []byte(plainstring))

	aliceCipher, err := GetPublickeyCipher(pass, salt, alicekey, bobpub)
	if err != nil {
		t.Fatalf("Failed to get decrypt cipher: %v", err)
	}
	decryptedData, err := DecryptString(aliceCipher, cipherstring)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if plainstring != string(decryptedData) {
		t.Fatalf("Decrypted data not correct")
	}
}
