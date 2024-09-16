
from cortado.rtas import load_all_modules, get_registry

def test_load_all_modules():

    # All RTA modules must be imported without issues
    load_all_modules()

    registry = get_registry()

    # Continuously changing number of RTAs
    assert len(registry) == 552
