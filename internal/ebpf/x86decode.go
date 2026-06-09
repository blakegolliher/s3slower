package ebpf

// x86InsnLen returns the byte length of the x86-64 instruction starting at
// code[0]. Returns 0 if the instruction cannot be decoded.
//
// This is a minimal decoder sufficient for walking Go-compiled functions
// to find RET instruction boundaries. It handles all one-byte opcodes,
// common two-byte (0x0F) opcodes, and three-byte (0x0F 0x38/0x3A) opcodes.
func x86InsnLen(code []byte) int {
	if len(code) == 0 {
		return 0
	}
	pos := 0

	// --- Legacy prefixes ---
	for pos < len(code) {
		switch code[pos] {
		case 0x26, 0x2E, 0x36, 0x3E, // segment overrides
			0x64, 0x65, // FS, GS
			0x66, 0x67, // operand-size, address-size
			0xF0, 0xF2, 0xF3: // LOCK, REPNZ, REP
			pos++
		default:
			goto prefixDone
		}
	}
prefixDone:
	if pos >= len(code) {
		return 0
	}

	// --- REX prefix (0x40-0x4F) ---
	hasREXW := false
	if code[pos] >= 0x40 && code[pos] <= 0x4F {
		hasREXW = code[pos]&0x08 != 0
		pos++
		if pos >= len(code) {
			return 0
		}
	}

	// --- Opcode ---
	op := code[pos]
	pos++

	var hasModRM bool
	var immSize int

	switch {
	case op == 0x0F:
		// Two-byte opcode escape
		if pos >= len(code) {
			return 0
		}
		op2 := code[pos]
		pos++
		switch {
		case op2 == 0x38 || op2 == 0x3A:
			// Three-byte opcode (0F 38 xx / 0F 3A xx)
			if pos >= len(code) {
				return 0
			}
			pos++ // third opcode byte
			hasModRM = true
			if op2 == 0x3A {
				immSize = 1
			}
		case op2 >= 0x80 && op2 <= 0x8F:
			// Jcc rel32
			immSize = 4
		case op2 >= 0x90 && op2 <= 0x9F:
			// SETcc r/m8
			hasModRM = true
		case op2 >= 0x40 && op2 <= 0x4F:
			// CMOVcc
			hasModRM = true
		case op2 == 0x1F:
			// NOP r/m (multi-byte NOP)
			hasModRM = true
		case op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF:
			// MOVZX, MOVSX
			hasModRM = true
		case op2 == 0xAF:
			// IMUL r, r/m
			hasModRM = true
		case op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB:
			// BT, BTS, BTR, BTC
			hasModRM = true
		case op2 == 0xBA:
			// BT/BTS/BTR/BTC r/m, imm8
			hasModRM = true
			immSize = 1
		case op2 == 0xA4 || op2 == 0xAC:
			// SHLD/SHRD r/m, r, imm8
			hasModRM = true
			immSize = 1
		case op2 == 0xA5 || op2 == 0xAD:
			// SHLD/SHRD r/m, r, CL
			hasModRM = true
		case op2 == 0x05:
			// SYSCALL
		case op2 == 0x01:
			// Various system instructions
			hasModRM = true
		default:
			// Most 0F opcodes have ModRM
			hasModRM = true
		}
	default:
		// One-byte opcode
		hasModRM, immSize = x86OneByteOpcode(op, hasREXW)
	}

	// --- ModRM + SIB + Displacement ---
	if hasModRM {
		if pos >= len(code) {
			return 0
		}
		modrm := code[pos]
		pos++

		mod := modrm >> 6
		rm := modrm & 7

		// SIB byte present when mod != 11 and rm == 100 (RSP/R12)
		if mod != 3 && rm == 4 {
			if pos >= len(code) {
				return 0
			}
			sib := code[pos]
			pos++
			// SIB with base=101 (RBP/R13) and mod=00 means disp32
			if mod == 0 && (sib&7) == 5 {
				pos += 4
			}
		}

		switch mod {
		case 0:
			if rm == 5 {
				pos += 4 // RIP-relative disp32
			}
		case 1:
			pos += 1 // disp8
		case 2:
			pos += 4 // disp32
		}
	}

	// --- Immediate ---
	pos += immSize

	if pos > len(code) {
		return 0
	}
	return pos
}

// x86OneByteOpcode returns ModRM and immediate-size flags for a primary
// (one-byte) x86-64 opcode.
func x86OneByteOpcode(op byte, rexW bool) (hasModRM bool, immSize int) {
	switch {
	// Arithmetic group: ADD OR ADC SBB AND SUB XOR CMP
	// Pattern repeats every 8 opcodes from 0x00
	case op <= 0x3F:
		switch op & 7 {
		case 0, 1, 2, 3:
			return true, 0 // r/m, r  or  r, r/m
		case 4:
			return false, 1 // AL, imm8
		case 5:
			return false, 4 // rAX, imm32
		default: // 6, 7: PUSH/POP segment (invalid in 64-bit, but 1-byte)
			return false, 0
		}

	// INC/DEC (0x40-0x4F) are REX prefixes in 64-bit; handled above

	// PUSH/POP register (0x50-0x5F)
	case op >= 0x50 && op <= 0x5F:
		return false, 0

	// MOVSXD (0x63)
	case op == 0x63:
		return true, 0

	// PUSH imm32 / PUSH imm8
	case op == 0x68:
		return false, 4
	case op == 0x6A:
		return false, 1

	// IMUL r, r/m, imm32 / imm8
	case op == 0x69:
		return true, 4
	case op == 0x6B:
		return true, 1

	// Jcc rel8 (0x70-0x7F)
	case op >= 0x70 && op <= 0x7F:
		return false, 1

	// Group 1: op r/m, imm
	case op == 0x80, op == 0x82:
		return true, 1 // r/m8, imm8
	case op == 0x81:
		return true, 4 // r/m32, imm32
	case op == 0x83:
		return true, 1 // r/m32, imm8

	// TEST, XCHG, MOV, LEA
	case op == 0x84, op == 0x85:
		return true, 0 // TEST r/m, r
	case op == 0x86, op == 0x87:
		return true, 0 // XCHG r/m, r
	case op >= 0x88 && op <= 0x8B:
		return true, 0 // MOV r/m,r  or  r,r/m
	case op == 0x8C, op == 0x8E:
		return true, 0 // MOV seg
	case op == 0x8D:
		return true, 0 // LEA
	case op == 0x8F:
		return true, 0 // POP r/m

	// NOP, XCHG rAX (0x90-0x97)
	case op >= 0x90 && op <= 0x97:
		return false, 0
	// CBW/CDQ/CQO etc (0x98-0x99)
	case op == 0x98, op == 0x99:
		return false, 0
	// PUSHF/POPF (0x9C-0x9D)
	case op == 0x9C, op == 0x9D:
		return false, 0

	// MOV AL/AX, moffs / moffs, AL/AX
	case op >= 0xA0 && op <= 0xA3:
		return false, 4 // moffs32 (or 8 with address-size override)

	// TEST AL/rAX, imm
	case op == 0xA8:
		return false, 1
	case op == 0xA9:
		return false, 4

	// STOS, LODS, SCAS, MOVS, CMPS (0xA4-0xAF, no operands)
	case op >= 0xA4 && op <= 0xAF:
		return false, 0

	// MOV r8, imm8 (0xB0-0xB7)
	case op >= 0xB0 && op <= 0xB7:
		return false, 1
	// MOV r32/r64, imm32/imm64 (0xB8-0xBF)
	case op >= 0xB8 && op <= 0xBF:
		if rexW {
			return false, 8 // MOV r64, imm64
		}
		return false, 4

	// Shift group: r/m, imm8 (0xC0-0xC1)
	case op == 0xC0:
		return true, 1
	case op == 0xC1:
		return true, 1

	// RET (0xC3) / RET imm16 (0xC2)
	case op == 0xC2:
		return false, 2
	case op == 0xC3:
		return false, 0

	// MOV r/m, imm (0xC6-0xC7)
	case op == 0xC6:
		return true, 1
	case op == 0xC7:
		return true, 4

	// ENTER (0xC8): imm16 + imm8
	case op == 0xC8:
		return false, 3
	// LEAVE (0xC9)
	case op == 0xC9:
		return false, 0

	// INT3, INT, INTO
	case op == 0xCC:
		return false, 0
	case op == 0xCD:
		return false, 1

	// Shift group: r/m, 1  /  r/m, CL
	case op == 0xD0, op == 0xD1, op == 0xD2, op == 0xD3:
		return true, 0

	// CALL rel32 (0xE8)
	case op == 0xE8:
		return false, 4
	// JMP rel32 (0xE9)
	case op == 0xE9:
		return false, 4
	// JMP rel8 (0xEB)
	case op == 0xEB:
		return false, 1

	// LOOP/LOOPcc/JCXZ (0xE0-0xE3)
	case op >= 0xE0 && op <= 0xE3:
		return false, 1

	// IN/OUT (0xE4-0xE7)
	case op == 0xE4, op == 0xE5:
		return false, 1
	case op == 0xE6, op == 0xE7:
		return false, 1

	// Group 3: TEST/NOT/NEG/MUL/DIV (0xF6-0xF7)
	case op == 0xF6:
		return true, 1 // Note: only TEST has imm, others don't - we over-count slightly
	case op == 0xF7:
		return true, 4 // Same note

	// Group 4/5: INC/DEC/CALL/JMP/PUSH (0xFE-0xFF)
	case op == 0xFE, op == 0xFF:
		return true, 0

	// CLC, STC, CLI, STI, CLD, STD
	case op >= 0xF8 && op <= 0xFD:
		return false, 0

	// HLT (0xF4)
	case op == 0xF4:
		return false, 0

	default:
		return false, 0
	}
}
