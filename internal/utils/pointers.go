package utils

// Ptr returns a pointer to the given string.
// This helper is useful for creating pointers to string literals in struct initializations.
func Ptr(s string) *string {
	return &s
}

// PtrInt returns a pointer to the given int.
func PtrInt(i int) *int {
	return &i
}

// PtrBool returns a pointer to the given bool.
func PtrBool(b bool) *bool {
	return &b
}
