package threshold

import (
	"errors"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44/internal"
)

// PublicKey is a standard ML-DSA-44 public key; verify with mldsa44.Verify.
type PublicKey = mldsa44.PublicKey

// SignatureSize is the size of a standard ML-DSA-44 signature.
const SignatureSize = mldsa44.SignatureSize

// KeyShare is one party's RSS share of the signing key: one (s1, s2) share per subset of N-T+1 parties it belongs to.
type KeyShare struct {
	id     uint8
	params *Params
	rho    [32]byte // seed of A
	tr     [64]byte // H(pk)
	s1     []internal.VecL
	s2     []internal.VecK
}

// ID returns the party index in [0, N).
func (ks *KeyShare) ID() uint8 { return ks.id }

// Params returns the parameters the share was generated with.
func (ks *KeyShare) Params() *Params { return ks.params }

var errNotImplemented = errors.New("mldsa44/threshold: not implemented yet")

// GenerateKeys returns a public key and N key shares (paper Fig. 5).
func GenerateKeys(rand io.Reader, p *Params) (*PublicKey, []*KeyShare, error) {
	_, _ = rand, p
	return nil, nil, errNotImplemented
}

// Round1State is private state carried from Round1 to Round2.
type Round1State struct{}

// Round1 samples K masks y_i, computes w_i = A·y_i and returns a hash commitment to them.
func Round1(ks *KeyShare, rand io.Reader) (msg []byte, st *Round1State, err error) {
	_, _ = ks, rand
	return nil, nil, errNotImplemented
}

// Round2State is private state carried from Round2 to Round3.
type Round2State struct{}

// Round2 reveals w_i after all Round1 hashes are known; active lists the T signing party IDs.
func Round2(ks *KeyShare, st *Round1State, active []uint8, msg, ctx []byte, round1 [][]byte) ([]byte, *Round2State, error) {
	_, _, _, _, _, _ = ks, st, active, msg, ctx, round1
	return nil, nil, errNotImplemented
}

// Round3 derives the challenge from the summed w and returns z_i = y_i + c·s1_i, or an abort.
func Round3(ks *KeyShare, st *Round2State, round2 [][]byte) ([]byte, error) {
	_, _, _ = ks, st, round2
	return nil, errNotImplemented
}

// Combine sums the responses into a standard ML-DSA-44 signature (paper Fig. 7); needs no secret.
func Combine(pk *PublicKey, p *Params, msg, ctx []byte, round2, round3 [][]byte, sig []byte) error {
	_, _, _, _, _, _, _ = pk, p, msg, ctx, round2, round3, sig
	return errNotImplemented
}
