import csv
import os

from aggregator.config import Config
from aggregator.shared.exceptions import ContractsNotFoundException
from aggregator.shared.singleton import SingletonMeta
from aggregator.shared.utils import *

FILE_COLUMN = 0
NAME_COLUMN = 1
VULNERABILITIES_COLUMN = 2
LINK_COLUMN = 3


class ContractService(metaclass=SingletonMeta):
    """sertice that contains operations with the available contracts
    """

    def __init__(self) -> None:
        self._config = Config()

    def list_contracts_from_contract_list(self, for_smartian: bool) -> list:
        """lists the contracts from the contracts.csv file
        """
        contracts_folder = os.path.join(
            self._config.temp_folder, self._config.inputs_folder)
        if not os.path.exists(contracts_folder):
            raise ContractsNotFoundException(
                "the contracts were not downloaded yet. Please use the command download_contracts first")

        contracts = []
        map_vul = map_vulnerability_to_smartian_standard if for_smartian else map_vulnerability_to_dogefuzz_standard
        contracts_csv = os.path.join(contracts_folder, "contracts.csv")
        with open(contracts_csv, 'r', encoding="utf-8") as file:
            reader = csv.reader(file)
            for row in reader:
                contract = {
                    "file": row[FILE_COLUMN],
                    "name": row[NAME_COLUMN],
                    "vulnerabilities": [x for x in [map_vul(x) for x in row[VULNERABILITIES_COLUMN].split(";")] if x is not None],
                    "link": row[LINK_COLUMN],                
                }
                if for_smartian:
                    contract["vulnerabilities"] =  list(set(contract["vulnerabilities"]))
                contracts.append(contract)

        return contracts
