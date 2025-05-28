grep -Prl "disable_fun" /etc/ | xargs sed -ri "s/^(disable_fun.*)/\1e, exec, system, shell_exec, passthru, popen, curl_exec, curl_multi_exec, parse_ini_file, show_source, proc_open, pcntl_exec"

for file in $(find /etc -name php.ini 2>/dev/null); do
    echo -e "expose_php = Off \ntrack_errors = Off \nhtml_errors = Off \ndisplay_errors = Of \nmagic_quotes_gpc = Off \n allow_url_fopen = Off \n allow_url_include = Off \n register_globals = Off \n file_uploads = Off \n session.cookie_httponly = 1\n$(cat $file) > $file"
done 

for ini in $(find /etc -name php.ini 2>/dev/null); do
    echo "expose_php = Off" >> $ini
    echo "track_errors = Off" >> $ini
    echo "html_errors = Off" >> $ini
    echo "file_uploads = Off" >> $ini
    echo "session.cookie_httponly = 1" >> $ini
    echo "disable_functions = exec, system, shell_exec, passthru, popen, curl_exec, curl_multi_exec, parse_ini_file, show_source, proc_open, pcntl_exec" >> $ini
	echo "max_execution_time = 3" >> $ini
	echo "register_globals = off" >> $ini
	echo "magic_quotes_gpc = on" >> $ini
	echo "allow_url_fopen = off" >> $ini
	echo "allow_url_include = off" >> $ini
	echo "display_errors = off" >> $ini
	echo "short_open_tag = off" >> $ini
	echo "session.cookie_httponly = 1" >> $ini
	echo "session.use_only_cookies = 1" >> $ini
	echo "session.cookie_secure = 1" >> $ini
done 