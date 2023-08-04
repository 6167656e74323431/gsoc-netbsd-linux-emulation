atf_test_case init
init_head() {
	atf_set "descr" "Tests inotify_init applies its flags correctly"
}

init_body() {

	atf_check -s exit:0 \
		"$(atf_get_srcdir)/tc_inotify_init"
}

atf_init_test_cases() {
	atf_add_test_case init
}
