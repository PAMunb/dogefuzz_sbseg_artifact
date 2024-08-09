import os
import json
import numpy as np
from collections import Counter
import csv


from matplotlib import pyplot as plt
from sklearn.cluster import KMeans
import matplotlib.ticker as mtick

from aggregator.config import Config

from aggregator.services.result import ResultService
from aggregator.shared.constants import BLACKBOX_FUZZING, DIRECTED_GREYBOX_FUZZING, GREYBOX_FUZZING, OTHER_GREYBOX_FUZZING
from aggregator.shared.singleton import SingletonMeta
from aggregator.shared.utils import *


FUZZING_TYPES = [BLACKBOX_FUZZING, DIRECTED_GREYBOX_FUZZING, GREYBOX_FUZZING, OTHER_GREYBOX_FUZZING]

class OutputService(metaclass=SingletonMeta):

    def __init__(self) -> None:
        self._config = Config()
        self._result_service = ResultService()

    def write_report(self, results_folder_name: str, contracts: list, for_smartian: bool, not_labeled: bool):
        """
        writes the output to the output file
        """
        results_folder = os.path.join(
            self._config.results_folder, results_folder_name)

        critical_instructions = [
            "CALL",
            "SELFDESCTRUCT",
            "CALLCODE",
            "DELEGATECALL",
        ]

        if not for_smartian:
            vulnerability_types = [
                "delegate",
                "exception-disorder",
                "gasless-send",
                "number-dependency",
                "reentrancy",
                "timestamp-dependency",
            ]
        else:
            vulnerability_types = [
                "BD",
                "ME",
                "RE",
            ]

        if not_labeled:
            for strategy in FUZZING_TYPES:
                output_file_path = os.path.join(results_folder, f"bugs_over_time-{strategy}.txt")                

                if os.path.exists(output_file_path):
                    os.remove(output_file_path)

                with open(output_file_path, 'w', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    self._write_vulnerabilities_csv_not_labeled_time(writer, contracts, vulnerability_types, strategy)
                
        output_file_path = os.path.join(results_folder, "average.txt")

        if os.path.exists(output_file_path):
            os.remove(output_file_path)

        with open(output_file_path, "wt", encoding="utf-8") as f:
            self._write_line(f, 'AVERAGE RESULTS')
            self._write_transaction_count(f, contracts)
            self._write_max_coverage_result(f, contracts)
            self._write_average_coverage_result(f, contracts)
            # self._write_critial_instructions_hits(f, contracts)executions_by_contract_name[contract_name]
            self._write_critial_instructions_detailed_hits(
                f, contracts, critical_instructions)
            
            if not_labeled:
                self._write_vulnerabilities_not_labeled(
                    f, contracts, vulnerability_types)
            else:
                self._write_vulnerabilities(
                    f, contracts, vulnerability_types, False)
                

        if for_smartian:
            for strategy in FUZZING_TYPES:
                output_file_path = os.path.join(results_folder, f"smartian-{strategy}.txt")

                if os.path.exists(output_file_path):
                    os.remove(output_file_path)

                with open(output_file_path, "wt", encoding="utf-8") as f:
                    self._write_vulnerabilities_table_per_contract(f, contracts, vulnerability_types, strategy)

                output_cov_file = os.path.join(results_folder, f"smartian-cov-{strategy}.txt")

                if os.path.exists(output_cov_file):
                    os.remove(output_cov_file)

                with open(output_cov_file, "wt", encoding="utf-8") as f:
                    self._write_coverage_table_over_time(f, contracts, strategy)

                # Alarms file
                output_alarms_file = os.path.join(results_folder, f"smartian-alarms-{strategy}.txt")

                if os.path.exists(output_alarms_file):
                    os.remove(output_alarms_file)

                with open(output_alarms_file, "wt", encoding="utf-8") as f:
                    self._write_alarms_table(f, contracts, strategy, vulnerability_types)



        for vulnerability_type in vulnerability_types:
            file_path = os.path.join(
                results_folder, f"vulnerability-{vulnerability_type}.txt")
            if os.path.exists(file_path):
                os.remove(file_path)
            filtered_contracts = []
            for contract in contracts:
                for vulnerability in contract["vulnerabilities"]:
                    if vulnerability == vulnerability_type:
                        filtered_contracts.append(contract)
            with open(file_path, "wt", encoding="utf-8") as f:
                self._write_line(f, f'{vulnerability_type.upper()} RESULTS')
                self._write_max_coverage_result(f, filtered_contracts)
                self._write_average_coverage_result(f, filtered_contracts)
                self._write_critial_instructions_detailed_hits(
                    f, filtered_contracts, critical_instructions)
                if not_labeled:
                    self._write_vulnerabilities_not_labeled(
                        f, contracts, vulnerability_types)
                else:
                    self._write_vulnerabilities(
                        f, contracts, vulnerability_types, False)

        inputs_file_folder = os.path.join(
            self._config.temp_folder, self._config.inputs_folder)
        inputs_file = os.path.join(inputs_file_folder, "inputs.json")

        dataset_array = []
        contracts_name = None
        with open(inputs_file, 'r', encoding='utf-8') as f:
            inputs = json.load(f)
            contracts_name = [0] * len(inputs)
            for idx, contract in enumerate(inputs):
                contract_name = contract['name']
                contracts_name[idx] = contract_name
                row = [contract['numberOfBranches'], sum(
                    contract["numberOfCriticalInstructions"].values())]
                dataset_array.append(row)
        kmeans = KMeans(
            n_clusters=3,
            init='random',
            n_init=10,
            max_iter=100,
        )
        kmeans.fit(np.array(dataset_array))

        clusters = {}
        letters = ['A', 'B', 'C']
        for idx, cluster in enumerate(kmeans.labels_):
            key = letters[cluster]
            if key not in clusters:
                clusters[key] = []
            contract_info = [
                contract for contract in contracts if contract['name'] == contracts_name[idx]]
            if len(contract_info) > 0:
                clusters[key].append(contract_info[0])

        for key, contracts in clusters.items():
            file_path = os.path.join(
                results_folder, f"cluster-group-{key.lower()}.txt")
            if os.path.exists(file_path):
                os.remove(file_path)
            with open(file_path, "wt", encoding="utf-8") as f:
                self._write_line(f, f'GROUP {key.upper()} RESULTS')
                self._write_max_coverage_result(f, contracts)
                self._write_average_coverage_result(f, contracts)
                # self._write_critial_instructions_hits(f, contracts)
                self._write_critial_instructions_detailed_hits(
                    f, contracts, critical_instructions)
                if not_labeled:
                    self._write_vulnerabilities_not_labeled(
                        f, contracts, vulnerability_types)
                else:
                    self._write_vulnerabilities(
                        f, contracts, vulnerability_types, False)
                
    def get_max_coverage_result(self, contracts: list):
        
        (max_coverage_per_contract_for_blackbox, average_coverage_for_blackbox) = self._result_service.get_max_coverage_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
        )
        (max_coverage_per_contract_for_greybox, average_coverage_for_greybox) = self._result_service.get_max_coverage_by_strategy(
            GREYBOX_FUZZING,
            contracts,
        )
        (max_coverage_per_contract_for_directed_greybox, average_coverage_for_directed_greybox) = self._result_service.get_max_coverage_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
        )

        (max_coverage_per_contract_for_other_directed_greybox, average_coverage_for_other_directed_greybox) = self._result_service.get_max_coverage_by_strategy(
            OTHER_GREYBOX_FUZZING,
            contracts,
        )

        blackbox_per_list = []
        greybox_per_list = []
        directed_greybox_per_list = []
        
        for contract in contracts:
            contract_name = contract["file"]
            
            blackbox = max_coverage_per_contract_for_blackbox[
                contract_name] if contract_name in max_coverage_per_contract_for_blackbox else -1
            greybox = max_coverage_per_contract_for_greybox[
                contract_name] if contract_name in max_coverage_per_contract_for_greybox else -1
            directed_greybox = max_coverage_per_contract_for_directed_greybox[
                contract_name] if contract_name in max_coverage_per_contract_for_directed_greybox else -1
            other_directed_greybox = max_coverage_per_contract_for_other_directed_greybox[
                contract_name] if contract_name in max_coverage_per_contract_for_other_directed_greybox else -1

            blackbox_per_list.append(100*blackbox)
            greybox_per_list.append(100*greybox)
            directed_greybox_per_list.append(100*directed_greybox)

            percentage_blackbox = self._convert_to_percentage_str(blackbox)
            
            percentage_greybox = self._convert_to_percentage_diff_str(
                greybox, blackbox)
            
            percentage_directed_greybox = self._convert_to_percentage_diff_str(
                directed_greybox, blackbox)

            percentage_other_directed_greybox = self._convert_to_percentage_diff_str(
                other_directed_greybox, blackbox)

        return (blackbox_per_list, greybox_per_list, directed_greybox_per_list), (average_coverage_for_blackbox*100,
            average_coverage_for_greybox*100,
            average_coverage_for_directed_greybox*100)
        
    def _write_max_coverage_result(self, file, contracts: list):
        
        (max_coverage_per_contract_for_blackbox, average_coverage_for_blackbox) = self._result_service.get_max_coverage_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
        )
        (max_coverage_per_contract_for_greybox, average_coverage_for_greybox) = self._result_service.get_max_coverage_by_strategy(
            GREYBOX_FUZZING,
            contracts,
        )
        (max_coverage_per_contract_for_directed_greybox, average_coverage_for_directed_greybox) = self._result_service.get_max_coverage_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
        )

        (max_coverage_per_contract_for_other_directed_greybox, average_coverage_for_other_directed_greybox) = self._result_service.get_max_coverage_by_strategy(
            OTHER_GREYBOX_FUZZING,
            contracts,
        )

        self._write_header(file, 'MAX COVERAGE RESULTS', "contract")

        for contract in contracts:
            contract_name = contract["file"]
            
            blackbox = max_coverage_per_contract_for_blackbox[
                contract_name] if contract_name in max_coverage_per_contract_for_blackbox else -1
            greybox = max_coverage_per_contract_for_greybox[
                contract_name] if contract_name in max_coverage_per_contract_for_greybox else -1
            directed_greybox = max_coverage_per_contract_for_directed_greybox[
                contract_name] if contract_name in max_coverage_per_contract_for_directed_greybox else -1
            other_directed_greybox = max_coverage_per_contract_for_other_directed_greybox[
                contract_name] if contract_name in max_coverage_per_contract_for_other_directed_greybox else -1


            percentage_blackbox = self._convert_to_percentage_str(blackbox)
            
            percentage_greybox = self._convert_to_percentage_diff_str(
                greybox, blackbox)
            
            percentage_directed_greybox = self._convert_to_percentage_diff_str(
                directed_greybox, blackbox)

            percentage_other_directed_greybox = self._convert_to_percentage_diff_str(
                other_directed_greybox, blackbox)

            self._write_line(
                file, f"| {contract_name:45} | {percentage_blackbox:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} | {percentage_other_directed_greybox:20} |")

        self._write_average_footer(
            file,
            average_coverage_for_blackbox,
            average_coverage_for_greybox,
            average_coverage_for_directed_greybox,
            average_coverage_for_other_directed_greybox
        )

    def _write_average_coverage_result(self, file, contracts: list):
        (average_coverage_per_contract_for_blackbox, average_converage_for_blackbox) = self._result_service.get_average_coverage_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
        )
        (average_coverage_per_contract_for_greybox, average_coverage_for_greybox) = self._result_service.get_average_coverage_by_strategy(
            GREYBOX_FUZZING,
            contracts,
        )
        (average_coverage_per_contract_for_directed_greybox, average_coverage_for_directed_greybox) = self._result_service.get_average_coverage_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
        )

        (average_coverage_per_contract_for_other_directed_greybox, average_coverage_for_other_directed_greybox) = self._result_service.get_average_coverage_by_strategy(
            OTHER_GREYBOX_FUZZING,
            contracts,
        )

        self._write_header(file, 'AVERAGE COVERAGE RESULTS', "contract")

        for contract in contracts:
            contract_name = contract["file"]
            blackbox = average_coverage_per_contract_for_blackbox[
                contract_name] if contract_name in average_coverage_per_contract_for_blackbox else -1
            greybox = average_coverage_per_contract_for_greybox[
                contract_name] if contract_name in average_coverage_per_contract_for_greybox else -1
            directed_greybox = average_coverage_per_contract_for_directed_greybox[
                contract_name] if contract_name in average_coverage_per_contract_for_directed_greybox else -1

            other_directed_greybox = average_coverage_per_contract_for_other_directed_greybox[
                contract_name] if contract_name in average_coverage_per_contract_for_other_directed_greybox else -1

            percentage_blackbox = self._convert_to_percentage_str(blackbox)
            percentage_greybox = self._convert_to_percentage_diff_str(
                greybox, blackbox)
            percentage_directed_greybox = self._convert_to_percentage_diff_str(
                directed_greybox, blackbox)

            percentage_other_directed_greybox = self._convert_to_percentage_diff_str(
                other_directed_greybox, blackbox)

            self._write_line(
                file, f"| {contract_name:45} | {percentage_blackbox:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} | {percentage_other_directed_greybox:20} |")

        self._write_average_footer(
            file,
            average_converage_for_blackbox,
            average_coverage_for_greybox,
            average_coverage_for_directed_greybox,
            average_coverage_for_other_directed_greybox
        )

    def _write_critial_instructions_hits(self, file, contracts: list):
        (hits_per_contract_for_blackbox, average_hits_for_blackbox) = self._result_service.get_hits_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
        )
        (hits_per_contract_for_greybox, average_hits_for_greybox) = self._result_service.get_hits_by_strategy(
            GREYBOX_FUZZING,
            contracts,
        )
        (hits_per_contract_for_directed_greybox, average_hits_for_directed_greybox) = self._result_service.get_hits_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
        )

        (hits_per_contract_for_other_directed_greybox, average_hits_for_other_directed_greybox) = self._result_service.get_hits_by_strategy(
            OTHER_GREYBOX_FUZZING,
            contracts,
        )

        self._write_header(file, 'CRITICAL INSTRUCTIONS HITS RESULTS', "instruction")

        for contract in contracts:
            contract_name = contract["file"]
            blackbox = hits_per_contract_for_blackbox[
                contract_name] if contract_name in hits_per_contract_for_blackbox else -1
            greybox = hits_per_contract_for_greybox[
                contract_name] if contract_name in hits_per_contract_for_greybox else -1
            directed_greybox = hits_per_contract_for_directed_greybox[
                contract_name] if contract_name in hits_per_contract_for_directed_greybox else -1
            other_directed_greybox = hits_per_contract_for_other_directed_greybox[
                contract_name] if contract_name in hits_per_contract_for_other_directed_greybox else -1


            hits_for_blackbox = self._convert_to_str(blackbox)
            hits_for_greybox = self._convert_to_diff_str(greybox, blackbox)
            hits_for_directed_greybox = self._convert_to_diff_str(
                directed_greybox, blackbox)

            hits_for_other_directed_greybox = self._convert_to_diff_str(
                other_directed_greybox, blackbox)

            self._write_line(
                file, f"| {contract_name:45} | {hits_for_blackbox:20} | {hits_for_greybox:20} | {hits_for_directed_greybox:20} | {hits_for_other_directed_greybox:20} |")
        self._write_average_number_footer(
            file,
            average_hits_for_blackbox,
            average_hits_for_greybox,
            average_hits_for_directed_greybox,
            average_hits_for_other_directed_greybox
        )

    def _write_critial_instructions_detailed_hits(self, file, contracts: list, critical_instructions: list):
        (hits_per_instruction_for_blackbox, average_hits_for_blackbox) = self._result_service.get_hits_by_instructions_and_strategy(
            BLACKBOX_FUZZING,
            contracts,
            critical_instructions,
        )
        (hits_per_instruction_for_greybox, average_hits_for_greybox) = self._result_service.get_hits_by_instructions_and_strategy(
            GREYBOX_FUZZING,
            contracts,
            critical_instructions,
        )
        (hits_per_instruction_for_directed_greybox, average_hits_for_directed_greybox) = self._result_service.get_hits_by_instructions_and_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
            critical_instructions,
        )

        (hits_per_instruction_for_other_directed_greybox, average_hits_for_other_directed_greybox) = self._result_service.get_hits_by_instructions_and_strategy(
            OTHER_GREYBOX_FUZZING,
            contracts,
            critical_instructions,
        )

        self._write_header(file, 'DETAILED CRITICAL INSTRUCTIONS HITS RESULTS', "instruction")

        for critical_instruction in critical_instructions:
            blackbox = hits_per_instruction_for_blackbox[
                critical_instruction] if critical_instruction in hits_per_instruction_for_blackbox else -1
            greybox = hits_per_instruction_for_greybox[
                critical_instruction] if critical_instruction in hits_per_instruction_for_greybox else -1
            directed_greybox = hits_per_instruction_for_directed_greybox[
                critical_instruction] if critical_instruction in hits_per_instruction_for_directed_greybox else -1

            other_directed_greybox = hits_per_instruction_for_other_directed_greybox[
                critical_instruction] if critical_instruction in hits_per_instruction_for_other_directed_greybox else -1


            hits_for_blackbox = self._convert_to_str(blackbox)
            hits_for_greybox = self._convert_to_diff_str(greybox, blackbox)
            hits_for_directed_greybox = self._convert_to_diff_str(
                directed_greybox, blackbox)

            hits_for_other_directed_greybox = self._convert_to_diff_str(
                other_directed_greybox, blackbox)

            self._write_line(
                file, f"| {critical_instruction:45} | {hits_for_blackbox:20} | {hits_for_greybox:20} | {hits_for_directed_greybox:20} | {hits_for_other_directed_greybox:20} |")

        self._write_average_number_footer(
            file,
            average_hits_for_blackbox,
            average_hits_for_greybox,
            average_hits_for_directed_greybox,
            average_hits_for_other_directed_greybox
        )

    def _write_vulnerabilities_not_labeled(
        self,
        file,
        contracts: list,
        vulnerability_types: list
    ):
        detection_rate_for_blackbox = self._result_service.get_detection_rate_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
            vulnerability_types,
            True,
        )
        detection_rate_for_greybox = self._result_service.get_detection_rate_by_strategy(
            GREYBOX_FUZZING,
            contracts,
            vulnerability_types,
            True,
        )
        detection_rate_for_directed_greybox = self._result_service.get_detection_rate_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
            vulnerability_types,
            True,
        )

        detection_rate_for_other_directed_greybox = self._result_service.get_detection_rate_by_strategy(
            OTHER_GREYBOX_FUZZING,
            contracts,
            vulnerability_types,
            True,
        )

        self._write_header(file, 'VULNERABILITIES RESULTS', "vulnerability type")
                 
        total_blackbox = 0
        total_greybox = 0
        total_directed_greybox = 0
        total_other_directed_greybox = 0

        
        for vulnerability in vulnerability_types:
            blackbox = detection_rate_for_blackbox[vulnerability][1]
            greybox = detection_rate_for_greybox[vulnerability][1]
            directed_greybox = detection_rate_for_directed_greybox[vulnerability][1]
            other_directed_greybox = detection_rate_for_other_directed_greybox[vulnerability][1]

            total_blackbox += detection_rate_for_blackbox[vulnerability][1]
            total_greybox += detection_rate_for_greybox[vulnerability][1]
            total_directed_greybox += detection_rate_for_directed_greybox[vulnerability][1]
            total_other_directed_greybox += detection_rate_for_other_directed_greybox[vulnerability][1]            
                        
            detection_rate_for_greybox[vulnerability][1]
            self._write_line(
                file, f"| {vulnerability:45} | {blackbox:20} | {greybox:20} | {directed_greybox:20} | {other_directed_greybox:20} |")


        if (len(vulnerability_types) > 1):
            self._write_average_number_footer(
                file,
                total_blackbox,
                total_greybox,
                total_directed_greybox,
                total_other_directed_greybox
            )
        else:
            self._write_dashed_line(file)

    def _write_vulnerabilities(
        self,
        file,
        contracts: list,
        vulnerability_types: list,
        include_new_detections: bool = False,
    ):
        detection_rate_for_blackbox = self._result_service.get_detection_rate_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
            vulnerability_types,
            include_new_detections,
        )
        detection_rate_for_greybox = self._result_service.get_detection_rate_by_strategy(
            GREYBOX_FUZZING,
            contracts,
            vulnerability_types,
            include_new_detections,
        )
        detection_rate_for_directed_greybox = self._result_service.get_detection_rate_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
            vulnerability_types,
            include_new_detections,
        )

        detection_rate_for_other_directed_greybox = self._result_service.get_detection_rate_by_strategy(
            OTHER_GREYBOX_FUZZING,
            contracts,
            vulnerability_types,
            include_new_detections,
        )

        self._write_header(file, 'VULNERABILITIES RESULTS', "vulnerability type")
        
        vul_count = self._result_service.get_vulnerabilities_count(contracts, vulnerability_types)
     
        average_detection_rate_for_blackbox = 0
        average_detection_rate_for_greybox = 0
        average_detection_rate_for_directed_greybox = 0
        average_detection_rate_for_other_directed_greybox = 0        
        
        total_blackbox = 0
        total_greybox = 0
        total_directed_greybox = 0
        total_other_directed_greybox = 0

        
        for vulnerability in vulnerability_types:
            blackbox = detection_rate_for_blackbox[vulnerability][0]
            greybox = detection_rate_for_greybox[vulnerability][0]
            directed_greybox = detection_rate_for_directed_greybox[vulnerability][0]
            other_directed_greybox = detection_rate_for_other_directed_greybox[vulnerability][0]            

            percentage_blackbox = self._convert_to_percentage_str(blackbox)
            
            percentage_greybox = self._convert_to_percentage_diff_str_with_total(
                greybox, blackbox, detection_rate_for_greybox[vulnerability][1])
            
            percentage_directed_greybox = self._convert_to_percentage_diff_str_with_total(
                directed_greybox, blackbox, detection_rate_for_directed_greybox[vulnerability][1])

            percentage_other_directed_greybox = self._convert_to_percentage_diff_str_with_total(
                other_directed_greybox, blackbox, detection_rate_for_other_directed_greybox[vulnerability][1])

            average_detection_rate_for_blackbox += blackbox
            average_detection_rate_for_greybox += greybox
            average_detection_rate_for_directed_greybox += directed_greybox
            average_detection_rate_for_other_directed_greybox += other_directed_greybox            

            total_blackbox += detection_rate_for_blackbox[vulnerability][1]
            total_greybox += detection_rate_for_greybox[vulnerability][1]
            total_directed_greybox += detection_rate_for_directed_greybox[vulnerability][1]
            total_other_directed_greybox += detection_rate_for_other_directed_greybox[vulnerability][1]            
            
            vulnerability_text = vulnerability + " (" + str(vul_count[vulnerability]) + ")"
            percentage_blackbox_text = percentage_blackbox + " (" + str(detection_rate_for_blackbox[vulnerability][1]) + ")"
            
            self._write_line(
                file, f"| {vulnerability_text:45} | {percentage_blackbox_text:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} | {percentage_other_directed_greybox:20} |")

        average_blackbox = average_detection_rate_for_blackbox / \
            len(vulnerability_types)
        average_greybox = average_detection_rate_for_greybox / \
            len(vulnerability_types)
        average_directed_greybox = average_detection_rate_for_directed_greybox / \
            len(vulnerability_types)
        average_other_directed_greybox = average_detection_rate_for_other_directed_greybox / \
            len(vulnerability_types)


        if (len(vulnerability_types) > 1):
            self._write_average_footer_with_total(
                file, sum(vul_count.values()),
                average_blackbox, total_blackbox,
                average_greybox, total_greybox,
                average_directed_greybox, total_directed_greybox,
                average_other_directed_greybox, total_other_directed_greybox
            )
        else:
            self._write_dashed_line(file)

    def _count_found_before(self, bug_sigs, time_map, sec):
        n = 0
        for (targ, found_bug) in time_map:
            found_time = time_map[(targ, found_bug)]
            if found_bug in bug_sigs and found_time < sec:
                n += 1
        return n

    def _write_count_over_time_frame(
        self,
        file,
        vulnerability_types: list,        
        time_map_list: list,
        time_frame_in_seconds: int,
        upper_limit_in_seconds: int
    ):                    
        for time in range(0, upper_limit_in_seconds + time_frame_in_seconds, time_frame_in_seconds):
            sec = time
            bug_sigs = list(map(lambda x: map_vulnerability_smartian_to_long_name(x), vulnerability_types))
            count_list = []
            for time_map in time_map_list:
                count_list.append(self._count_found_before(bug_sigs, time_map, sec))
            count_avg = float(sum(count_list)) / len(count_list)
            self._write_line(file, f"{time:02d}s: {count_avg:.1f}")

    def _write_count_over_time(
        self,
        file,
        vulnerability_types: list,        
        time_map_list: list
    ):                    
        for minute in range(0, 60 + 5, 5):
            sec = 60 * minute
            bug_sigs = list(map(lambda x: map_vulnerability_smartian_to_long_name(x), vulnerability_types))
            count_list = []
            for time_map in time_map_list:
                count_list.append(self._count_found_before(bug_sigs, time_map, sec))
            count_avg = float(sum(count_list)) / len(count_list)
            self._write_line(file, f"{minute:02d}m: {count_avg:.1f}")

    def _write_vulnerabilities_table_per_contract(
        self,
        file,
        contracts: list,
        vulnerability_types: list, 
        strategy: str,        
    ):                    
        detected_true_positive, time_map_list = self._result_service.get_detection_by_strategy(strategy, contracts, vulnerability_types)
        for vulnerability_type in vulnerability_types:
            for line in detected_true_positive[vulnerability_type]:
                self._write_line(file, f"{line}")
            self._write_line(file, "===================================")
        if len(time_map_list) != 0:
            self._write_count_over_time(file, vulnerability_types, time_map_list)
            self._write_line(file, "===================================TIME_FRAME")
            self._write_count_over_time_frame(file, vulnerability_types, time_map_list, 15, 300)

    def _write_vulnerabilities_csv_not_labeled_time(
        self,
        file,
        contracts: list,
        vulnerability_types: list,
        strategy: str
    ):                    
        detected = self._result_service.get_detection_by_strategy_csv(strategy, contracts)
        for row in detected:
            file.writerow(row)



    def _write_alarms_table(
        self,
        file,
        contracts: list,
        strategy: str,        
        vulnerability_types: list        
    ):
        
        self._write_line(file, "===================================")        
        alarms = self._result_service.get_detection_alarms(strategy, contracts, vulnerability_types, False)
        for vulnerability_type in vulnerability_types:
            tp = (alarms[vulnerability_type]["TP"])
            fp = (alarms[vulnerability_type]["FP"])
            fn = (alarms[vulnerability_type]["FN"])
            self._write_line(
                file, f"{map_vulnerability_smartian_to_long_name(vulnerability_type):30}: TP = {tp:2}, FP = {fp:2}, FN = {fn:2}")
                
    def _write_coverage_table_over_time(
        self,
        file,
        contracts: list,
        strategy: str,        
    ):                    
        coverage_map = self._result_service.get_instructions_coverage(strategy, contracts)
        
        total_coverage_over_time = Counter()
        for _, _, coverage_over_time in coverage_map.values():
            total_coverage_over_time += Counter(coverage_over_time)
        final_dict_cov = dict(total_coverage_over_time)
        self._write_line(file, f"{0:02d}m: {0:.1f}")
        for minute, total in final_dict_cov.items():
            self._write_line(file, f"{minute:02d}m: {total:.1f}")

    def _write_transaction_count(self, file, contracts: list):
        transaction_count_for_blackbox = self._result_service.get_transaction_count_by_strategy(
            BLACKBOX_FUZZING,
            contracts,
        )
        transaction_count_for_greybox = self._result_service.get_transaction_count_by_strategy(
            GREYBOX_FUZZING,
            contracts,
        )
        transaction_count_for_directed_greybox = self._result_service.get_transaction_count_by_strategy(
            DIRECTED_GREYBOX_FUZZING,
            contracts,
        )

        transaction_count_for_other_directed_greybox = self._result_service.get_transaction_count_by_strategy(
            OTHER_GREYBOX_FUZZING,
            contracts,
        )

        self._write_header(file, 'TRANSACTION COUNT RESULTS', "count")

        blackbox = self._convert_to_str(transaction_count_for_blackbox)
        greybox = self._convert_to_diff_str(
            transaction_count_for_greybox, transaction_count_for_blackbox)
        directed_greybox = self._convert_to_diff_str(
            transaction_count_for_directed_greybox, transaction_count_for_blackbox)

        other_directed_greybox = self._convert_to_diff_str(
            transaction_count_for_other_directed_greybox, transaction_count_for_blackbox)

        self._write_line(
            file, f"| {'transaction_count':45} | {blackbox:20} | {greybox:20} | {directed_greybox:20} | {other_directed_greybox:20} |")

        self._write_dashed_line(file)

    def _write_header(self, file, title: str, text: str):
        self._write_line(file, "\n")
        self._write_line(file, title)
        self._write_dashed_line(file)
        self._write_line(
            file, f"| {text:45} | {'blackbox':20} | {'greybox':20} | {'directed_greybox':20} | {'other_directed_greybox':20} |")
        self._write_dashed_line(file)

    def _write_average_footer(
        self,
        file,
        average_blackbox,
        average_greybox,
        average_directed_greybox,
        average_other_directed_greybox,
    ):
        percentage_blackbox = self._convert_to_percentage_str(average_blackbox)
        percentage_greybox = self._convert_to_percentage_diff_str(
            average_greybox, average_blackbox)
        percentage_directed_greybox = self._convert_to_percentage_diff_str(
            average_directed_greybox, average_blackbox)

        percentage_other_directed_greybox = self._convert_to_percentage_diff_str(
            average_other_directed_greybox, average_blackbox)

        self._write_dashed_line(file)
        self._write_line(
            file, f"| {'AVERAGE':45} | {percentage_blackbox:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} | {percentage_other_directed_greybox:20} |")
        self._write_dashed_line(file)

    def _write_average_footer_with_total(
        self,
        file, total_vulnerabilities,
        average_blackbox, total_blackbox,
        average_greybox, total_greybox,
        average_directed_greybox, total_directed_greybox,
        average_other_directed_greybox, total_other_directed_greybox        
    ):
        percentage_blackbox = self._convert_to_percentage_str(average_blackbox)
        percentage_greybox = self._convert_to_percentage_diff_str_with_total(
            average_greybox, average_blackbox, total_greybox)
        percentage_directed_greybox = self._convert_to_percentage_diff_str_with_total(
            average_directed_greybox, average_blackbox, total_directed_greybox)

        percentage_other_directed_greybox = self._convert_to_percentage_diff_str_with_total(
            average_other_directed_greybox, average_blackbox, total_other_directed_greybox)

        percentage_blackbox_text = percentage_blackbox + " (" + str(total_blackbox) + ")"
        total_vulnerabilities_text = "AVERAGE" + " (" + str(total_vulnerabilities) + ")"

        self._write_dashed_line(file)
        self._write_line(
            file, f"| {total_vulnerabilities_text:45} | {percentage_blackbox_text:20} | {percentage_greybox:20} | {percentage_directed_greybox:20} | {percentage_other_directed_greybox:20} |")
        self._write_dashed_line(file)

    def _write_average_number_footer(
        self,
        file,
        average_blackbox,
        average_greybox,
        average_directed_greybox,
        average_other_directed_greybox,
    ):
        number_blackbox = self._convert_to_str(average_blackbox)
        number_greybox = self._convert_to_diff_str(
            average_greybox, average_blackbox)
        number_directed_greybox = self._convert_to_diff_str(
            average_directed_greybox, average_blackbox)

        number_other_directed_greybox = self._convert_to_diff_str(
            average_other_directed_greybox, average_blackbox)

        self._write_dashed_line(file)
        self._write_line(
            file, f"| {'AVERAGE':45} | {number_blackbox:20} | {number_greybox:20} | {number_directed_greybox:20} | {number_other_directed_greybox:20} |")
        self._write_dashed_line(file)

    def _convert_to_str(self, value) -> str:
        return f"{value:.2f}" if value != -1 else "N/A"

    def _convert_to_percentage_str(self, value) -> str:
        return f"{value * 100:.2f}%" if value != -1 else "N/A"

    def _convert_to_diff_str(self, value, base_value) -> str:
        if base_value == 0:
            diff = 1 if value != 0 else 0
        else:
            diff = (value - base_value) / base_value
        return f"{value:.2f} ({'+' if diff > 0 else ''}{diff * 100:.2f}%)" if value != -1 else "N/A"

    def _convert_to_percentage_diff_str(self, value, base_value) -> str:
        if base_value == 0:
            diff = 1 if value != 0 else 0
        else:
            diff = (value - base_value) / base_value
        return f"{value * 100:.2f}% ({'+' if diff > 0 else ''}{diff * 100:.2f}%)" if value != -1 else "N/A"

    def _convert_to_percentage_diff_str_with_total(self, value, base_value, total) -> str:
        if base_value == 0:
            diff = 1 if value != 0 else 0
        else:
            diff = (value - base_value) / base_value
        return f"{value * 100:.2f}% ({total:02d},{'+' if diff > 0 else ''}{diff * 100:.2f}%)" if value != -1 else "N/A"

    def _write_dashed_line(self, file):
        self._write_line(file, '-' * 142)

    def _write_line(self, file, line: str):
        file.write(line + '\n')
