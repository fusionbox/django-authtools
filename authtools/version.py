import subprocess

STAGE = 'final'

VERSION = (1, 0, 0, STAGE)


def get_version():
    number = '.'.join(map(str, VERSION[:3]))
    stage = VERSION[3]
    if stage == 'final':
        return number
    elif stage == 'alpha':
        process = subprocess.Popen('git rev-parse HEAD'.split(), stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return number + '-' + stdout.decode('utf-8').strip()[:8]
