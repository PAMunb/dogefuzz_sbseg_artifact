"""
this module contains the exceptions used by this project
"""


class ContractsNotFoundException(Exception):
    """the exception is raised when the contracts folder doesn't exist
    """

    def __init__(self, *args: object) -> None:
        super().__init__(*args)
