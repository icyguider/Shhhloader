#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import random
import struct


def get_old_seed():
	with open('Syscalls.h') as f:
		code = f.read()
	match = re.search(r'#define SW2_SEED (0x[a-fA-F0-9]{8})', code)
	assert match is not None, 'SW2_SEED not found!'
	return match.group(1)


def replace_seed(old_seed, new_seed):
	with open('Syscalls.h') as f:
		code = f.read()
	code = code.replace(
		f'#define SW2_SEED {old_seed}',
		f'#define SW2_SEED 0x{new_seed:08X}',
		1
	)
	with open('Syscalls.h', 'w') as f:
		f.write(code)


def get_function_hash(seed, function_name):
	function_hash = seed
	if function_name[:2] == 'Nt':
		function_name = 'Zw' + function_name[2:]
	name = function_name + '\0'
	ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

	for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
		partial_name_short = struct.unpack('<H', segment.encode())[0]
		function_hash ^= partial_name_short + ror8(function_hash)

	return function_hash


def replace_syscall_hashes(seed):
	with open('Syscalls.h') as f:
		code = f.read()
	regex = re.compile(r'#define (Nt[^(]+) ')
	syscall_names = re.findall(regex, code)
	syscall_names = set(syscall_names)
	syscall_definitions = code.split('EXTERN_C DWORD SW2_GetSyscallNumber')[2]

	for syscall_name in syscall_names:
		regex = re.compile('#define ' + syscall_name + '.*?mov ecx, (0x0[A-Fa-f0-9]{8})', re.DOTALL)
		match = re.search(regex, syscall_definitions)
		assert match is not None, f'hash of syscall {syscall_name} not found!'
		old_hash = match.group(1)
		new_hash = get_function_hash(seed, syscall_name)
		print(f'{syscall_name} -> {old_hash} -> 0x0{new_hash:08X}')
		code = code.replace(
			old_hash,
			f'0x0{new_hash:08X}'
		)

	with open('Syscalls.h', 'w') as f:
		f.write(code)


def main():
	new_seed = random.randint(2 ** 28, 2 ** 32 - 1)
	#new_seed = 0x1337C0DE
	old_seed = get_old_seed()
	replace_seed(old_seed, new_seed)
	replace_syscall_hashes(new_seed)
	print('done!')


if __name__ == '__main__':
	main()
