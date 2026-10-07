package tsaudit

// crcTable is the MPEG-2 CRC-32 table (polynomial 0x04C11DB7, MSB first).
var crcTable [256]uint32

func init() {
	for i := 0; i < 256; i++ {
		crc := uint32(i) << 24
		for j := 0; j < 8; j++ {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
		crcTable[i] = crc
	}
}

// CRC32MPEG returns the MPEG-2 CRC-32 of b (init 0xFFFFFFFF, no reflection,
// no final XOR). Checking a byte range that includes its trailing CRC field
// yields 0 when the CRC is correct.
func CRC32MPEG(b []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, v := range b {
		crc = crc<<8 ^ crcTable[byte(crc>>24)^v]
	}
	return crc
}
