//go:build cgo && idissnative && windows

package native

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../idiss/target/release -lidiss
*/
import "C"
