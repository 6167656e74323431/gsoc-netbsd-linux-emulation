h_ensure_emul_exists() {
	modstat | grep -q '^compat_linux\W' \
		|| atf_skip "Linux emulation not loaded"
}
