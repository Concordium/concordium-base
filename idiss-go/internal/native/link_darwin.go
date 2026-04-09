//go:build cgo && idissnative && darwin

package native

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../idiss/target/release -lidiss -Wl,-rpath,${SRCDIR}/../../../idiss/target/release
*/
import "C"
