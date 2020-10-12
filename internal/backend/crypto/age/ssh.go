package age

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/gopasspw/gopass/internal/debug"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"golang.org/x/crypto/ssh"
)

var (
	sshCache map[string]age.Identity
)

const (
	ExtensionType = "decrypt@age-tool.com"
)

type Set map[string]struct{}

func NewSet(arr []string) Set {
	set := make(Set, len(arr))
	for _, v := range arr {
		set[v] = struct{}{}
	}
	return set
}

func (s Set) ToArray() (arr []string) {
	for k := range s {
		arr = append(arr, k)
	}
	return
}

func (a *Age) getAgentCallback(fingerprints Set) (DecryptCallback, error) {
	if a.ssha == nil {
		return nil, nil
	}
	keys, err := a.ssha.List()
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if _, ok := fingerprints[sshFingerprint(key.Marshal())]; ok {
			debug.Log("matching key: %s", key.Comment)
			return func(ciphertext []byte) ([]byte, error) {
				return a.ssha.Extension(ExtensionType, ciphertext)
			}, nil
		}
	}
	return nil, nil
}

func (a *Age) getAgentIdentities() (ids []string, _ error) {
	if a.ssha == nil {
		return nil, nil
	}
	keys, err := a.ssha.List()
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		ids = append(ids, key.Format+" "+base64.StdEncoding.EncodeToString(key.Blob)+" "+key.Comment)
	}
	return
}

func (a *Age) getSSHCallback(ctx context.Context, fingerprints Set) (DecryptCallback, error) {
	if sshCache != nil {
		for fingerprint := range fingerprints {
			if identity, ok := sshCache[fingerprint]; ok {
				return decryptCb(identity), nil
			}
		}
		return nil, nil
	}
	sshCache = map[string]age.Identity{}
	files, err := listSSHPubs()
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		recp, id, err := a.parseSSHIdentity(ctx, file)
		if err != nil {
			//debug.Log("Failed to parse SSH identity %s: %s", fn, err)
			continue
		}
		debug.Log("recipient: %s", recp)
		//debug.Log("parsed SSH identity %s from %s", recp, fn)
		sshCache[recp] = id
	}
	for fingerprint := range fingerprints {
		if identity, ok := sshCache[fingerprint]; ok {
			return decryptCb(identity), nil
		}
	}
	return nil, nil
}

func (a *Age) getSSHIdentities() (ids []string, _ error) {
	files, err := listSSHPubs()
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		pub, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, err
		}
		ids = append(ids, strings.TrimSpace(string(pub)))
	}
	return
}

func listSSHPubs() (pubs []string, _ error) {
	uhd, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	sshDir := filepath.Join(uhd, ".ssh")
	files, err := ioutil.ReadDir(sshDir)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		fn := filepath.Join(sshDir, file.Name())
		if !strings.HasSuffix(fn, ".pub") {
			continue
		}
		pubs = append(pubs, fn)
	}
	return
}

func (a *Age) parseSSHIdentity(ctx context.Context, pubFn string) (string, age.Identity, error) {
	privFn := strings.TrimSuffix(pubFn, ".pub")
	_, err := os.Stat(privFn)
	if err != nil {
		return "", nil, err
	}
	pubBuf, err := ioutil.ReadFile(pubFn)
	if err != nil {
		return "", nil, err
	}
	privBuf, err := ioutil.ReadFile(privFn)
	if err != nil {
		return "", nil, err
	}
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(pubBuf)
	if err != nil {
		return "", nil, err
	}
	recp := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pubkey)), "\n")
	id, err := agessh.ParseIdentity(privBuf)
	if err != nil {
		// handle encrypted SSH identities here
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			id, err := agessh.NewEncryptedSSHIdentity(pubkey, privBuf, func() ([]byte, error) {
				return ctxutil.GetPasswordCallback(ctx)(pubFn)
			})
			return recp, id, err
		}
		return "", nil, err
	}
	return recp, id, nil
}

func sshFingerprint(pk []byte) string {
	h := sha256.Sum256(pk)
	return EncodeToString(h[:4])
}

func decryptCb(identities ...age.Identity) DecryptCallback {
	return func(ciphertext []byte) ([]byte, error) {
		reader, err := age.Decrypt(bytes.NewBuffer(ciphertext), identities...)
		if err != nil {
			return nil, err
		}
		return ioutil.ReadAll(reader)
	}
}
