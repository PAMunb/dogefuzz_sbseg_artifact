from aggregator.shared.singleton import SingletonMeta


class Config(metaclass=SingletonMeta):
    def __init__(self) -> None:
        self.results_dir: str = "results"
        self.temp_folder: str = ".temp"
        self.resources_folder: str = "resources"
        self.inputs_folder: str = "inputs"
        self.results_folder: str = "results"
