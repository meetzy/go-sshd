package main

import (
	"github.com/meetzy/go-sshd"
	"golang.org/x/crypto/ssh"
)

func main() {
	s :=
		`-----BEGIN RSA PRIVATE KEY-----
	MIIEogIBAAKCAQEAzFsCQgkfIb7aOywCof2FcKZDJKeariwUI8bq3Vlv2TbGZqx3
	4W24j/e0RKq1aL2R0KuYtHRkerImnlJO3Yf1Y6qIPbJmZbrQqKD8AXBrwDZknuLb
	Qwgsi8X9dB+P3VoLf5StKwfO2TS9FVbKrtYAZnhGgqFdyzAUfuUorQuCMJjZDgtW
	psG7zZk/AcPSYrPi/orNB16wFgXwAE1P6eqVgf9dSmGd2R7AB/YdJNDc9CC0Qkcj
	++09QMyFs8msBUxtKPzrO+gamh6BTiwUsNBRrJof39Hm9ocTtMgc1Cdfsk5JpzmY
	lIawOFkf4iLj0ze9sYOCH4JRU7ud2QZsejilzQIDAQABAoIBAGLNZawTyO+B3PVa
	8/LqJkguuqvQNSMcwKgDlq5qfX9h0k71+AgQCnng41GHz6nSbdub+3rUA3inBbDq
	TqMhBu2nF7Psu0FYL2Y4X186wX3vTnrbZ/Ni0lbJ5R7t25rD3GdUtNznK4Us0Hau
	vdQGN69TW5Pw/O4uUtp/ZUk1FT706fZr6K45ZtdFuz1/k4EZCmXbr8X6uggWbO2o
	h+kR5Ko8OjQwefmTD+URZ6fr+bDFcYyX7T3wkLHpsLiIjfVE5gzpc3HmfXwHxbdF
	KXeoytv1MgyHIftBq1DehfqL3KP4a8VxgBwquFzD75yMlr2QxtN9losMAyFtP87o
	kVSgFYECgYEA8ys9a3cYrFbwC8pLUb/0utoy11D/tYolhdNjj64vMuuEANnIcocR
	Le2FHpBCFCmPUDT330PLFqv339vISHWq4CrF9saOEBbq47+EEsCoYzBGxBmxbH8r
	bgT+OLEv2l1+VaFr1tMM6H5IFcVuNy/I9U1NnU2nFwCMiMl/grZHb50CgYEA1yN4
	0Z9Ml7DcA7uf/GN/alYYWLfzVI8jD4JU4rgKlJCwnbuyoj9AkkeswlSa7CwoDPUC
	66upGhIe+Nk0/tBa9aMqTMUoy3UmUasSdET4W0qSrw6vdhmsa1FPlIfpIU+qUnAu
	b+YyiGfVUH6wiyP2OHsvRL96xqZ+jmTbeAxJ7/ECgYAaB0vYv/PFJr0lFe8//eMN
	SSPeBk6IuRPRIlJq48MrmSgVCzq4f5qoJt9z6Q8Zp2Uuuay6mkAX2ip7LMRgdS/o
	NMvh4Vj9geZ8oFhbxYGAtH8uqG1kZqxYZ3Jq0RSFNDK8qb2oTgj4reO7aNmmUJgb
	Ib4oE1LKVIW2cpMSg75bxQKBgHE+Ub19rbJ3PQiV/Zu7v/j4Qq6IfYQ4KAtk3kvM
	9nzHQMB2aYwv4UxegBh2smm4wIg5fAUTgdqgST9SDixG/mooLf7lFRkrnDUG6Jrd
	JyHeuiF9iGyRDQocbdhQRi3rokrsk/UA5f6ZMVbCqSlEj7mhVftJE1Z3k0xe2Itz
	ZIPxAoGAceIC5GLrk6sQeI5cuqGjFZEQlYuIdOzBinR4S1tms9akSYaKvf3MjtPU
	wDnAhxXbU1ePBwbsSi2q9RW9BKmWI1sxiB/Th+5k0DQYrbmt2dR7WTQ7iWYFjQrL
	mfWU1KZE2MaVY4YbUjEvlV0l/5cNVX8jjTOOd3FYI10ntsr1oZY=
		-----END RSA PRIVATE KEY-----`

	serverConfig := &ssh.ServerConfig{
		ServerVersion:     "SSH-2.0-ambari-agent",
		PasswordCallback:  passwordCallback,
		PublicKeyCallback: publicKeyCallback,
	}

	key, _ := ssh.ParsePrivateKey([]byte(s))
	serverConfig.AddHostKey(key)

	sshServer := &sshd.SSHServer{
		Port:    7777,
		Address: "127.0.0.1",
		Server:  serverConfig,
	}
	sshServer.Start()
}

func publicKeyCallback(remoteConn ssh.ConnMetadata, remoteKey ssh.PublicKey) (*ssh.Permissions, error) {
	return nil, nil
}

func passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	return nil, nil
}
