atf_test_case init
init_head() {
	atf_set "descr" "Tests inotify_init applies its flags correctly"
}

init_body() {

	atf_check -s exit:0 \
		"$(atf_get_srcdir)/h_inotify_init"
}

atf_test_case single_file
single_file_head() {
	atf_set "descr" \
		"Tests correct events are generated when a single file is watched"
}

single_file_body() {

	atf_check -s exit:0 \
		"$(atf_get_srcdir)/h_inotify_single_file"
}

atf_test_case watch_change
watch_change_head() {
	atf_set "descr" \
		"Tests the watch descriptor can be modified"
}

watch_change_body() {

	atf_check -s exit:0 \
		"$(atf_get_srcdir)/h_inotify_watch_change"
}

atf_init_test_cases() {
	atf_add_test_case init
	atf_add_test_case single_file
	atf_add_test_case watch_change
}
