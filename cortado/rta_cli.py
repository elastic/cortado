import sys


# CLI interface with the bare-minimum dependencies

def run_rta():
    if len(sys.argv) != 2:
        print("RTA name is not provided")
        sys.exit(1)

    rta_name = sys.argv[1]
    print("HELLO RTA", rta_name)


def print_rtas():
    print("HELLO PRINT RTAS", sys.argv)
