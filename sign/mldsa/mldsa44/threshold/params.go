package threshold

import (
	"errors"
	"fmt"
)

// MaxParties is the largest supported N; RSS needs C(N, N-T+1) shares so groups stay small.
const MaxParties = 6

// Params is the threshold configuration shared by all parties.
type Params struct {
	T uint8 // parties needed to sign
	N uint8 // total parties
	// TODO: per-(T,N) protocol parameters K, r, r', nu (paper §3.2).
}

// ErrInvalidParams is returned for (T, N) outside 2 <= T <= N <= MaxParties.
var ErrInvalidParams = errors.New("mldsa44/threshold: invalid threshold parameters")

// NewParams returns the parameters for a T-out-of-N group.
func NewParams(t, n uint8) (*Params, error) {
	if t < 2 || t > n || n > MaxParties {
		return nil, fmt.Errorf("%w: T=%d N=%d", ErrInvalidParams, t, n)
	}
	return &Params{T: t, N: n}, nil
}

// NumShares is the number of additive key shares, C(N, N-T+1).
func (p *Params) NumShares() int {
	return binomial(int(p.N), int(p.N)-int(p.T)+1)
}

// SharesPerParty is the number of shares one party holds, C(N-1, N-T).
func (p *Params) SharesPerParty() int {
	return binomial(int(p.N)-1, int(p.N)-int(p.T))
}

// binomial returns C(n, k); inputs are bounded by MaxParties.
func binomial(n, k int) int {
	if k < 0 || k > n {
		return 0
	}
	if k > n-k {
		k = n - k
	}
	res := 1
	for i := 1; i <= k; i++ {
		res = res * (n - k + i) / i
	}
	return res
}
