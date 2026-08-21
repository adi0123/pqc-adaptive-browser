import os

# Set PQC_VERBOSE=1 in the environment to get the full old firehose of
# output (every secret, transcript hash, and per-connection performance
# report block). Off by default - the console instead shows one compact
# summary line per connection.
VERBOSE = os.environ.get("PQC_VERBOSE", "0") == "1"


def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)
