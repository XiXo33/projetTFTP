OK = '\033[92m'
END = '\033[0m'
WARNING = '\033[91m'
CYAN = '\033[96m'
YELLOW = '\033[33m'
PINK = '\033[95m'

def increment(a):
    """incrémente de 1 un byte"""
    a = int.from_bytes(a, byteorder='big') + 1
    return a.to_bytes(2, byteorder='big')


a = b'\x00\x01'

increment(a)
