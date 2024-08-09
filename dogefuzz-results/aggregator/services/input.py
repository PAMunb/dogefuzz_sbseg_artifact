"""
this module contains the logic of the inputs service
"""
import os
import zipfile
import shutil

from os import path

from aggregator.config import Config
from aggregator.shared.singleton import SingletonMeta


class InputService(metaclass=SingletonMeta):

    def __init__(self) -> None:
        self._config = Config()

    def extract_inputs(self, inputs_file: str):
        """
        extracts inputs from resources folder
        """
        inputs_folder = path.join(
            self._config.temp_folder, self._config.inputs_folder)
        inputs_zip_path = path.join(
            self._config.resources_folder, inputs_file)

        if path.exists(inputs_folder):
            shutil.rmtree(inputs_folder, ignore_errors=True)
        os.makedirs(inputs_folder)

        with zipfile.ZipFile(inputs_zip_path, 'r') as zip_file:
            zip_file.extractall(inputs_folder)
