# Disable PHP functions 
grep -Prl "disable_fun" /etc/ | xargs sed -ri "s/^(disable_fun.*)/\1e, exec, system, shell_exec, passthru, popen, curl_exec, curl_multi_exec, parse_ini_file, show_source, proc_open, pcntl_exec"

# Other PHP configs
for file in $(find /etc -name php.ini 2>/dev/null); do
    echo -e "expose_php = Off \ntrack_errors = Off \nhtml_errors = Off \ndisplay_errors = Of \nmagic_quotes_gpc = Off \n allow_url_fopen = Off \n allow_url_include = Off \n register_globals = Off \n file_uploads = Off \n session.cookie_httponly = 1\n$(cat $file) > $file"
done 
