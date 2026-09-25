import mylib

def handler():
    data = mylib.read_untrusted()      # custom source
    mylib.run_shell(data)              # custom sink -> should flag

def safe_handler():
    data = mylib.read_untrusted()
    mylib.run_shell(mylib.clean_cmd(data))   # custom sanitizer -> should NOT flag
