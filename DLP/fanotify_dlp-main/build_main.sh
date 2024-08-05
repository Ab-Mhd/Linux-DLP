gcc -o fanotify_dlp-main/main.out fanotify_dlp-main/main.c fanotify_dlp-main/rules.c fanotify_dlp-main/sensitive.c fanotify_dlp-main/audit.c -I/usr/local/include -L/usr/local/lib -lcjson -lm -pthread
