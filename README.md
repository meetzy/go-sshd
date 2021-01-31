# go-sshd

1. 实现了UNIX平台基本的shell操作
2. 添加了sftp的功能

# Thanks

* https://github.com/leechristensen/GolangSSHServer

```
var (
	// Public keys used for authentication.  Equivalent of the SSH authorized_hosts files
	authPublicKeys = map[string]string{
		"root": "AAAAC3NzaC1lZDI1NTE5AAAAIADi9ZoVZstck6ELY0EIB863kD4qp5i6DYpQJHkwBiEo",
	}
)

func DefaultPublicKeyCallback(remoteConn ssh.ConnMetadata, remoteKey ssh.PublicKey) (*ssh.Permissions, error) {
	log.Println("Trying to auth user " + remoteConn.User())

	authPublicKey, User := authPublicKeys[remoteConn.User()]
	if !User {
		log.Println("User does not exist")
		return nil, errors.New("user does not exist")
	}

	authPublicKeyBytes, err := base64.StdEncoding.DecodeString(authPublicKey)
	if err != nil {
		log.Println("Could not base64 decode key")
		return nil, errors.New("could not base64 decode key")
	}

	// Parse public key
	parsedAuthPublicKey, err := ssh.ParsePublicKey([]byte(authPublicKeyBytes))
	if err != nil {
		log.Println("could not parse public key")
		return nil, err
	}

	// Make sure the key types match
	if remoteKey.Type() != parsedAuthPublicKey.Type() {
		log.Println("Key types don't match")
		return nil, errors.New("key types do not match")
	}

	remoteKeyBytes := remoteKey.Marshal()
	authKeyBytes := parsedAuthPublicKey.Marshal()

	// Make sure the key lengths match
	if len(remoteKeyBytes) != len(authKeyBytes) {
		log.Println("Key lengths don't match")
		return nil, errors.New("keys do not match")
	}

	keysMatch := true
	for i, b := range remoteKeyBytes {
		if b != authKeyBytes[i] {
			keysMatch = false
		}
	}

	if keysMatch == false {
		log.Println("Keys don't match")
		return nil, errors.New("keys do not match")
	}
	return nil, nil
}
```