"""
this module contains metaclasses used in other parts of the project
reference: https://refactoring.guru/design-patterns/singleton/python/example#example-1
"""
from typing import Any


class SingletonMeta(type):
    """
    this class contains the implementation of the singleton pattern
    """
    _instances = {}

    def __call__(cls, *args: Any, **kwds: Any) -> Any:
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwds)
            cls._instances[cls] = instance
        return cls._instances[cls]
