
def skip(request, group, action=None, rate=None):
    return False


def deny(request, group, action=None, rate=None):
    return 1
