package threshold

import "math/bits"

// subsets returns every size-element subset of {0, ..., n-1} as a bitmask, in increasing order.
func subsets(n, size uint8) []uint8 {
	var out []uint8
	for m := uint8(0); m < 1<<n; m++ {
		if bits.OnesCount8(m) == int(size) {
			out = append(out, m)
		}
	}
	return out
}

// member reports whether party i is in the subset mask.
func member(mask, i uint8) bool { return mask&(1<<i) != 0 }
