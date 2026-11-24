//go:build !unix

package tree

// openFlags adds nothing on platforms without O_NONBLOCK.
const openFlags = 0
