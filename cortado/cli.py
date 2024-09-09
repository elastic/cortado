from cortado.rtas import load_all_modules, get_registry

def print_rtas():
    load_all_modules()
    registry = get_registry()
    sorted_names = sorted(registry.keys())

    for name in sorted_names:
        rta_details = registry[name]
        print(name, rta_details)


