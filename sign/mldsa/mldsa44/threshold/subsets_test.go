package threshold

import (
	"reflect"
	"testing"
)

func TestSubsets(t *testing.T) {
	// {0,1}=3, {0,2}=5, {1,2}=6: the three 2-subsets of {0,1,2}.
	if got := subsets(3, 2); !reflect.DeepEqual(got, []uint8{3, 5, 6}) {
		t.Errorf("subsets(3,2) = %v", got)
	}
	if got := subsets(4, 1); !reflect.DeepEqual(got, []uint8{1, 2, 4, 8}) {
		t.Errorf("subsets(4,1) = %v", got)
	}
	if got := len(subsets(6, 3)); got != 20 {
		t.Errorf("len(subsets(6,3)) = %d, want 20", got)
	}
	if !member(5, 2) || member(5, 1) {
		t.Error("member: wrong bit test")
	}
}
