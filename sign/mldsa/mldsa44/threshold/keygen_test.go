package threshold

import (
	"bytes"
	"math/bits"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44/internal"
)

func TestKeyGenRSS(t *testing.T) {
	for _, tn := range [][2]uint8{{2, 2}, {2, 3}, {3, 3}, {3, 5}, {4, 6}} {
		p, _ := NewParams(tn[0], tn[1])
		var seed [SeedSize]byte
		seed[0] = tn[0]
		seed[1] = tn[1]
		pk, shares := NewKeysFromSeed(&seed, p)

		if len(shares) != int(p.N) {
			t.Fatalf("(%d,%d): %d shares, want %d", p.T, p.N, len(shares), p.N)
		}
		all := subsets(p.N, p.N-p.T+1)
		var s1 internal.VecL
		var s2 internal.VecK
		for _, mask := range all {
			// Every party in the subset holds the same share, nobody else holds it.
			var first *KeyShare
			var j int
			for _, ks := range shares {
				idx := indexOf(ks.subsets, mask)
				if member(mask, ks.id) != (idx >= 0) {
					t.Fatalf("(%d,%d): party %d subset %06b membership mismatch", p.T, p.N, ks.id, mask)
				}
				if idx < 0 {
					continue
				}
				if first == nil {
					first, j = ks, idx
					s1.Add(&s1, &ks.s1[j])
					s2.Add(&s2, &ks.s2[j])
				} else if ks.s1[idx] != first.s1[j] || ks.s2[idx] != first.s2[j] {
					t.Fatalf("(%d,%d): subset %06b share differs between parties", p.T, p.N, mask)
				}
			}
		}
		for _, ks := range shares {
			if len(ks.s1) != p.SharesPerParty() {
				t.Fatalf("(%d,%d): party %d holds %d shares, want %d", p.T, p.N, ks.id, len(ks.s1), p.SharesPerParty())
			}
		}

		// Any T parties cover every subset, any T-1 parties miss at least one.
		for _, act := range subsets(p.N, p.T) {
			if n := coveredSubsets(shares, act); n != len(all) {
				t.Errorf("(%d,%d): active %06b covers %d of %d subsets", p.T, p.N, act, n, len(all))
			}
		}
		for _, act := range subsets(p.N, p.T-1) {
			if n := coveredSubsets(shares, act); n == len(all) {
				t.Errorf("(%d,%d): %d parties %06b should not cover all subsets", p.T, p.N, p.T-1, act)
			}
		}

		// The public key is the ML-DSA key of the summed shares.
		s1.Normalize()
		s2.Normalize()
		var A internal.Mat
		A.Derive(&shares[0].rho)
		want := packPublicKey(&A, &s1, &s2, &shares[0].rho)
		if got := pk.Bytes(); !bytes.Equal(got, want[:]) {
			t.Errorf("(%d,%d): public key does not match sum of shares", p.T, p.N)
		}
		if shares[0].tr != shares[p.N-1].tr {
			t.Errorf("(%d,%d): tr differs between parties", p.T, p.N)
		}
	}
}

func TestKeyGenDeterministic(t *testing.T) {
	p, _ := NewParams(2, 3)
	var seed [SeedSize]byte
	pk1, sh1 := NewKeysFromSeed(&seed, p)
	pk2, sh2 := NewKeysFromSeed(&seed, p)
	if !pk1.Equal(pk2) || sh1[1].s1[0] != sh2[1].s1[0] {
		t.Error("same seed gave different keys")
	}
	seed[0] = 1
	pk3, _ := NewKeysFromSeed(&seed, p)
	if pk1.Equal(pk3) {
		t.Error("different seeds gave the same public key")
	}
	if _, shares, err := GenerateKeys(nil, p); err != nil || len(shares) != 3 {
		t.Errorf("GenerateKeys: %v", err)
	}
}

func indexOf(masks []uint8, m uint8) int {
	for i, x := range masks {
		if x == m {
			return i
		}
	}
	return -1
}

// coveredSubsets counts the distinct shares held by the parties in act.
func coveredSubsets(shares []*KeyShare, act uint8) int {
	var seen uint64
	for _, ks := range shares {
		if member(act, ks.id) {
			for _, m := range ks.subsets {
				seen |= 1 << m
			}
		}
	}
	return bits.OnesCount64(seen)
}
