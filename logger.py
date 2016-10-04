def setup_logger(name, to_stderr=False):
    import logging
    import sys
    logger = logging.getLogger(name)
    handler = logging.StreamHandler(sys.stderr if to_stderr else sys.stdout)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger
