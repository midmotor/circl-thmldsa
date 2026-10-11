package threshold

import (
	cryptoRand "crypto/rand"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
	common "github.com/cloudflare/circl/sign/internal/dilithium"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44/internal"
)

// SeedSize is the size of the seed for NewKeysFromSeed.
const SeedSize = common.SeedSize

// GenerateKeys returns a public key and N key shares (paper Fig. 5); rand defaults to crypto/rand.
func GenerateKeys(rand io.Reader, p *Params) (*PublicKey, []*KeyShare, error) {
	if rand == nil {
		rand = cryptoRand.Reader
	}
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, nil, err
	}
	pk, shares := NewKeysFromSeed(&seed, p)
	return pk, shares, nil
}

// NewKeysFromSeed deterministically derives a public key and N key shares from seed.
func NewKeysFromSeed(seed *[SeedSize]byte, p *Params) (*PublicKey, []*KeyShare) {
	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Write([]byte{internal.K, internal.L, p.T, p.N})

	var rho [32]byte
	_, _ = h.Read(rho[:])
	var A internal.Mat
	A.Derive(&rho)

	shares := make([]*KeyShare, p.N)
	for i := range shares {
		shares[i] = &KeyShare{id: uint8(i), params: p, rho: rho}
	}

	// One short (s1, s2) per subset of N-T+1 parties; the full secret is their sum.
	var s1 internal.VecL
	var s2 internal.VecK
	for _, mask := range subsets(p.N, p.N-p.T+1) {
		var sSeed [64]byte
		_, _ = h.Read(sSeed[:])
		var s1j internal.VecL
		var s2j internal.VecK
		for i := uint16(0); i < internal.L; i++ {
			internal.PolyDeriveUniformLeqEta(&s1j[i], &sSeed, i)
		}
		for i := uint16(0); i < internal.K; i++ {
			internal.PolyDeriveUniformLeqEta(&s2j[i], &sSeed, i+internal.L)
		}
		s1.Add(&s1, &s1j)
		s2.Add(&s2, &s2j)
		for _, ks := range shares {
			if member(mask, ks.id) {
				ks.subsets = append(ks.subsets, mask)
				ks.s1 = append(ks.s1, s1j)
				ks.s2 = append(ks.s2, s2j)
			}
		}
	}
	s1.Normalize()
	s2.Normalize()

	packed := packPublicKey(&A, &s1, &s2, &rho)
	pk := new(internal.PublicKey)
	pk.Unpack(&packed)

	var tr [64]byte
	h.Reset()
	_, _ = h.Write(packed[:])
	_, _ = h.Read(tr[:])
	for _, ks := range shares {
		ks.tr = tr
	}
	return (*mldsa44.PublicKey)(pk), shares
}

// packPublicKey returns rho || t1 where (t0, t1) = Power2Round(A·s1 + s2), as in ML-DSA key generation.
func packPublicKey(A *internal.Mat, s1 *internal.VecL, s2 *internal.VecK, rho *[32]byte) [internal.PublicKeySize]byte {
	s1h := *s1
	s1h.NTT()
	var t, t0, t1 internal.VecK
	for i := 0; i < internal.K; i++ {
		internal.PolyDotHat(&t[i], &A[i], &s1h)
		t[i].ReduceLe2Q()
		t[i].InvNTT()
	}
	t.Add(&t, s2)
	t.Normalize()
	t.Power2Round(&t0, &t1)

	var buf [internal.PublicKeySize]byte
	copy(buf[:32], rho[:])
	t1.PackT1(buf[32:])
	return buf
}
