//go:build idissnative && idisswasm

package backend

func init() {
	panic("idissnative and idisswasm cannot be enabled at the same time")
}
