package threshold

import "testing"

func TestNewParams(t *testing.T) {
	valid := [][2]uint8{{2, 2}, {2, 3}, {3, 3}, {3, 5}, {4, 6}, {6, 6}}
	for _, tn := range valid {
		if _, err := NewParams(tn[0], tn[1]); err != nil {
			t.Errorf("NewParams(%d, %d): unexpected error %v", tn[0], tn[1], err)
		}
	}

	invalid := [][2]uint8{{0, 3}, {1, 3}, {4, 3}, {2, 7}, {0, 0}}
	for _, tn := range invalid {
		if _, err := NewParams(tn[0], tn[1]); err == nil {
			t.Errorf("NewParams(%d, %d): expected error", tn[0], tn[1])
		}
	}
}

func TestShareCounts(t *testing.T) {
	cases := []struct {
		t, n             uint8
		shares, perParty int
	}{
		{2, 2, 2, 1},
		{2, 3, 3, 2},
		{3, 3, 3, 1},
		{3, 5, 10, 6},
		{4, 6, 20, 10},
		{2, 6, 6, 5},
	}
	for _, c := range cases {
		p, err := NewParams(c.t, c.n)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.NumShares(); got != c.shares {
			t.Errorf("(%d,%d).NumShares() = %d, want %d", c.t, c.n, got, c.shares)
		}
		if got := p.SharesPerParty(); got != c.perParty {
			t.Errorf("(%d,%d).SharesPerParty() = %d, want %d", c.t, c.n, got, c.perParty)
		}
	}
}
