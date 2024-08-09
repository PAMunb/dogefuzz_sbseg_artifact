import os
import json
import numpy as np
import math
import glob
import re


from matplotlib import pyplot as plt
import mplcursors
from sklearn.cluster import KMeans
from itertools import cycle
import matplotlib.ticker as mtick

from aggregator.services.contract import ContractService
from aggregator.services.input import InputService
from aggregator.services.output import OutputService
from aggregator.services.result import ResultService
from aggregator.config import Config

MARKER_HOUR = "==================================="
MARKER_TIME_FRAME = "===================================TIME_FRAME"

linestyles = cycle([ '--'])
mainlinestyles = cycle(['-'])

class Aggregator():

    def __init__(self) -> None:
        self._input_service = InputService()
        self._contract_service = ContractService()
        self._result_service = ResultService()
        self._output_service = OutputService()
        self._config = Config()

    def generate_report(self, results_folder: str, inputs_file: str):
        self._input_service.extract_inputs(inputs_file)
        contracts = self._contract_service.list_contracts_from_contract_list(False)
        self._result_service.extract_results(results_folder)
        self._output_service.write_report(results_folder, contracts, False, False)

    def generate_report_not_labeled(self, results_folder: str, inputs_file: str):
        self._input_service.extract_inputs(inputs_file)
        contracts = self._contract_service.list_contracts_from_contract_list(False)
        self._result_service.extract_results(results_folder)
        self._output_service.write_report(results_folder, contracts, False, True)

    def generate_report_smartian(self, results_folder: str, inputs_file: str):
        self._input_service.extract_inputs(inputs_file)
        contracts = self._contract_service.list_contracts_from_contract_list(True)
        self._result_service.extract_results(results_folder)
        self._result_service.convert_results_to_smartian(results_folder)
        self._output_service.write_report(results_folder, contracts, True, False)

    def show_kmeans(self, cluster_number: int = 3):
        inputs_file_folder = os.path.join(
            self._config.temp_folder, self._config.inputs_folder)
        inputs_file = os.path.join(inputs_file_folder, "inputs.json")

        with open(inputs_file, 'r', encoding='utf-8') as f:
            inputs = json.load(f)
            dataset = np.array([[input['numberOfBranches'], sum(
                input['numberOfCriticalInstructions'].values())] for input in inputs])

            kmeans = KMeans(n_clusters=cluster_number, random_state=42, 
                            n_init=10, max_iter=100)
            kmeans.fit(dataset)

            plt.scatter(dataset[:, 0], dataset[:, 1], c=kmeans.labels_)
            plt.title('Clusterização dos Contratos')
            plt.xlabel('Número de Arestas')
            plt.xlim(-50, 450)
            plt.ylabel('Número de Instruções Críticas')
            plt.ylim(-5, 20)
            plt.grid()
            plt.show()

    def show_elbow_method(self):
        inputs_file_folder = os.path.join(
            self._config.temp_folder, self._config.inputs_folder)
        inputs_file = os.path.join(inputs_file_folder, "inputs.json")

        with open(inputs_file, 'r', encoding='utf-8') as f:
            inputs = json.load(f)
            dataset = np.array([[input['numberOfBranches'], sum(
                input['numberOfCriticalInstructions'].values())] for input in inputs])

            inertias = []

            for i in range(1, 11):
                kmeans = KMeans(n_clusters=i, n_init=10)
                kmeans.fit(dataset)
                inertias.append(kmeans.inertia_)

            plt.plot(range(1, 11), inertias, marker='o')
            plt.title('Método Elbow')
            plt.xlabel('Número de Clusters')
            plt.ylabel('Inercia')
            plt.show()

    def inputs_stats_smartian(self, inputs_file: str):
        self._input_service.extract_inputs(inputs_file)
        contracts = self._contract_service.list_contracts_from_contract_list(True)
        self._print_all(contracts)
        
    def inputs_stats(self, inputs_file: str):
        self._input_service.extract_inputs(inputs_file)
        contracts = self._contract_service.list_contracts_from_contract_list(False)

        self._print_all(contracts)

    def _print_all(self, contracts):
        vulnerabilities = {}
        for contract in contracts:
            for vulnerability in contract['vulnerabilities']:
                vulnerabilities[vulnerability] = vulnerabilities.get(
                    vulnerability, 0) + 1
                
                
        inputs_file_folder = os.path.join(
            self._config.temp_folder, self._config.inputs_folder)
        inputs_file = os.path.join(inputs_file_folder, "inputs.json")
                
        clusters = {}
        with open(inputs_file, 'r', encoding='utf-8') as f:
            inputs = json.load(f)
            dataset = np.array([[input['numberOfBranches'], sum(
                input['numberOfCriticalInstructions'].values())] for input in inputs])
            kmeans = KMeans(n_clusters=3, init='random',
                            n_init=10, max_iter=100)
            kmeans.fit(dataset)

            letters = ['A', 'B', 'C']
            for i in kmeans.labels_:
                clusters[letters[i]] = clusters.get(letters[i], 0) + 1

        print(f'Número de contratos: {len(contracts)}')
        print("------------------------------")
        print("Contratos por Vulnerabilidade:")
        for vulnerability, count in vulnerabilities.items():
            print(f'{vulnerability:20}: {count:5}')

        print("------------------------------")
        print("Contratos por Cluster:")
        for cluster, count in clusters.items():
            print(f'Cluster {cluster:1}: {count:5}')

    def show_correlation(self):
        delegate_data = [
            [26.67, 12.53, 0.75, 1],
            [26.67, 12.32, 0.76, 1],
            [33.33, 12.41, 0.80, 1],
            [40.00, 12.29, 0.82, 5],
            [46.67, 12.81, 0.82, 5],
            [33.33, 13.04, 0.91, 5],
            [40.00, 12.59, 0.77, 10],
            [46.67, 12.30, 0.70, 10],
            [53.33, 13.32, 0.84, 10],
        ]

        delegate_correlation = np.corrcoef(delegate_data, rowvar=False)
        print()
        print("Delegate Correlation Matrix")
        print("------------------------------")
        print(delegate_correlation)

        exception_disorder_data = [
            [37.50, 13.67, 1.66, 1],
            [33.33, 13.95, 1.82, 1],
            [41.67, 14.51, 1.71, 1],
            [58.33, 13.95, 1.61, 5],
            [58.33, 14.33, 1.72, 5],
            [54.17, 14.47, 1.65, 5],
            [58.33, 14.26, 1.67, 10],
            [66.67, 13.73, 1.69, 10],
            [62.50, 14.11, 1.67, 10],
        ]

        exception_disorder_correlation = np.corrcoef(
            exception_disorder_data, rowvar=False)
        print()
        print("Exception Disorder Correlation Matrix")
        print("------------------------------")
        print(exception_disorder_correlation)

        gasless_send_data = [
            [61.54, 10.63, 1.16, 1],
            [53.85, 10.84, 1.03, 1],
            [69.23, 10.62, 1.05, 1],
            [61.54, 10.69, 1.05, 5],
            [61.54, 10.77, 1.11, 5],
            [61.54, 10.98, 1.09, 5],
            [61.54, 10.82, 1.09, 10],
            [61.54, 10.82, 1.09, 10],
            [61.54, 10.86, 1.09, 10]
        ]

        gasless_send_correlation = np.corrcoef(
            gasless_send_data, rowvar=False)
        print()
        print("Gassless Send Correlation Matrix")
        print("------------------------------")
        print(gasless_send_correlation)

        number_dependency_data = [
            [5.63, 11.38, 3.34, 1],
            [8.45, 11.42, 3.66, 1],
            [9.86, 11.35, 3.19, 1],
            [7.04, 11.71, 3.55, 5],
            [11.27, 11.71, 3.61, 5],
            [11.27, 11.72, 3.48, 5],
            [7.04, 11.73, 3.31, 10],
            [11.27, 11.70, 3.50, 10],
            [11.27, 11.64, 3.44, 10]
        ]

        number_dependency_correlation = np.corrcoef(
            number_dependency_data, rowvar=False)
        print()
        print("Number Dependency Correlation Matrix")
        print("------------------------------")
        print(number_dependency_correlation)

        timestamp_dependency_data = [
            [10.91, 9.85, 3.94, 1],
            [17.27, 9.77, 3.95, 1],
            [13.64, 9.93, 3.58, 1],
            [12.73, 10.00, 3.90, 5],
            [18.18, 10.11, 4.07, 5],
            [17.27, 10.12, 3.83, 5],
            [16.36, 10.09, 3.92, 10],
            [21.82, 10.07, 3.81, 10],
            [19.09, 10.13, 3.96, 10]
        ]

        timestamp_dependency_correlation = np.corrcoef(
            timestamp_dependency_data, rowvar=False)
        print()
        print("Timestamp Dependency Correlation Matrix")
        print("------------------------------")
        print(timestamp_dependency_correlation)

        reentrancy_data = [
            [0.1, 13.92, 0.88, 1],
            [0.1, 13.90, 1.06, 1],
            [0.1, 13.39, 1.00, 1],
            [0.1, 14.53, 1.06, 5],
            [0.1, 14.13, 1.15, 5],
            [0.1, 14.12, 1.10, 5],
            [0.1, 14.42, 1.06, 10],
            [0.1, 14.02, 1.11, 10],
            [0.1, 13.91, 1.26, 10]
        ]

        reentrancy_correlation = np.corrcoef(
            reentrancy_data, rowvar=False)
        print()
        print("Reentrancy Correlation Matrix")
        print("------------------------------")
        print(reentrancy_correlation)


    def _read_data_between_markers(self, filename, start_marker, end_marker, keep_markers):
        try:
            with open(filename, 'r') as file:
                content = file.read()

                pattern = re.compile(re.escape(start_marker) + '(.*?)' + re.escape(end_marker), re.DOTALL)
                match = pattern.search(content)

                if match:
                    data_between_markers = match.group(1)
                    last_occurrence_index = data_between_markers.rfind(start_marker)
                    return data_between_markers[last_occurrence_index + len(start_marker):]
                else:
                    print(f"Start marker '{start_marker}' or end marker '{end_marker}' not found in the file.")
                    return None
        except FileNotFoundError:
            print(f"File '{filename}' not found.")
            return None

    def _read_data_after_marker(self, filename, marker, keep_marker):
        try:
            with open(filename, 'r') as file:
                content = file.read()

                last_occurrence_index = content.rfind(marker)

                if last_occurrence_index != -1:
                    # Extract data after the last occurrence of the delimiter
                    if keep_marker:
                        data_after_last_occurrence = content[last_occurrence_index:]
                    else:
                        data_after_last_occurrence = content[last_occurrence_index + len(marker):]
                    return data_after_last_occurrence
                else:
                    print(f"Delimiter '{marker}' not found in the file.")
                    return None

        except FileNotFoundError:
            print(f"File '{filename}' not found.")
            return None

    def smartian_b2_alarms_avg(self, results_folder: str, fuzz_type: str): 
        file_list = [file for file in glob.glob(os.path.join(results_folder, '')+"smartian-alarms-" + fuzz_type + '*.txt' )]

        if len(file_list) != 0:
            alarms_avg_map = {}
            vulnerabilities = ['BlockstateDependency', 'MishandledException', 'Reentrancy']
            for vulnerability in vulnerabilities:
                alarms_avg_map[vulnerability] = { "TP": [], "FP": [], "FN": [] }
                        
            for file_path in file_list:
                loaded_data = self._read_data_after_marker(file_path, MARKER_HOUR, False)
                lines = [line for line in loaded_data.split('\n') if line.strip() != ""]
                for line in lines:
                    vul, values = map(str, line.split(':'))
                    parts = values.split(',')
                    parts[0].strip().split('=')[1].strip()
                    alarms_avg_map[vul.strip()]["TP"].append(int(float(parts[0].strip().split('=')[1].strip())))
                    alarms_avg_map[vul.strip()]["FP"].append(int(float(parts[1].strip().split('=')[1].strip())))
                    alarms_avg_map[vul.strip()]["FN"].append(int(float(parts[2].strip().split('=')[1].strip())))

            print("===================================")
            for category in vulnerabilities:
                tp = np.median(alarms_avg_map[category]["TP"][:5])
                fp = np.median(alarms_avg_map[category]["FP"][:5])
                fn = np.median(alarms_avg_map[category]["FN"][:5])                                
                
                # tp = ((sum(alarms_avg_map[category]["TP"])) / len(alarms_avg_map[category]["TP"]))
                # fp = ((sum(alarms_avg_map[category]["FP"])) / len(alarms_avg_map[category]["FP"]))
                # fn = ((sum(alarms_avg_map[category]["FN"])) / len(alarms_avg_map[category]["FN"]))
                precision = tp/(tp+fp)
                recall = tp/(tp+fn)
                f1score = 2 * (precision * recall) / (precision + recall)
                
                print(f"{category:25}: TP = {tp:.2f}, FP = {fp:.2f}, FN = {fn:.2f} percision = {precision:.2f} recall = {recall:.2f} f1score = {f1score:.2f}")

    def count_smartian_b2_bugs_found_avg(self, results_folder: str, fuzz_type: str): 
        file_list = [file for file in glob.glob(os.path.join(results_folder, '')+"smartian-" + fuzz_type + '*.txt' )]
        
        if len(file_list) != 0:
            sum_values = []
            for file_path in file_list:
                loaded_data = self._read_data_between_markers(file_path, MARKER_HOUR, MARKER_TIME_FRAME, False)
                lines = [line for line in loaded_data.split('\n') if line.strip() != ""]    
                all_minutes = []
                all_values = []
                for line in lines:
                    minute, value = map(float, line.split('m:'))
                    all_minutes.append(minute)
                    all_values.append(value)
                sum_values.append(all_values)
                
            averages = [sum(row) / len(row) for row in zip(*sum_values)]
            print("===================================")
            for i, avg in enumerate(averages, start=0):
                print(f"{all_minutes[i]}m: {avg}")
        else:
            print("Invalid directory path.")
            return
        
    def count_smartian_b2_instruction_coverage_avg(self, results_folder: str, fuzz_type: str): 
        file_list = [file for file in glob.glob(os.path.join(results_folder, '')+"smartian-cov-" + fuzz_type + '*.txt' )]
        
        if len(file_list) != 0:
            sum_values = []
            for file_path in file_list:
                loaded_data = self._read_data_after_marker(file_path, "00m: 0.0", True)
                lines = [line for line in loaded_data.split('\n') if line.strip() != ""]    
                all_minutes = []
                all_values = []
                for line in lines:
                    minute, value = map(float, line.split('m:'))
                    all_minutes.append(int(minute))
                    all_values.append(value)
                sum_values.append(all_values)
                
            averages = [sum(row) / len(row) for row in zip(*sum_values)]
            print("===================================")
            for i, avg in enumerate(averages, start=0):
                print(f"{all_minutes[i]:02d}m: {avg}")
        else:
            print("Invalid directory path.")
            return

    def plot_smartian_b2_bugs_found_avg(self, results_folder: str): 
        if os.path.isdir(results_folder):
            file_list = [os.path.join(results_folder, file) for file in os.listdir(results_folder) if os.path.isfile(os.path.join(results_folder, file))]

            sum_values = []
            for file_path in file_list:
                loaded_data = self._read_data_after_marker(file_path, MARKER_HOUR, False)
                lines = [line for line in loaded_data.split('\n') if line.strip() != ""]    
                all_minutes = []
                all_values = []
                for line in lines:
                    minute, value = map(float, line.split('m:'))
                    all_minutes.append(minute)
                    all_values.append(value)
                sum_values.append(all_values)
                
            averages = [sum(row) / len(row) for row in zip(*sum_values)]
            plt.plot(all_minutes, averages, linestyle=next(linestyles), label="Avg of " + results_folder, linewidth=2.5)
            print("===================================")
            for i, avg in enumerate(averages, start=0):
                print(f"{all_minutes[i]}m: {avg}")
        else:
            print("Invalid directory path.")
            return
        
        mplcursors.cursor(hover=True).connect("add", lambda sel: sel.annotation.set_text(f"Bugs={sel.target[1]:.2f}"))
        plt.legend(loc='upper center', bbox_to_anchor=(0.5, 1.15), ncol=2) 
        plt.xlabel('Time (min.)')
        plt.ylabel('Total # of Bugs found')
        plt.grid(True)
        plt.show()

    def plot_smartian_b2_bugs_found(self, results_folder: str): 
        if os.path.isdir(results_folder):
            file_list = [os.path.join(results_folder, file) for file in os.listdir(results_folder) if os.path.isfile(os.path.join(results_folder, file))]

            for file_path in file_list:
                loaded_data = self._read_data_after_marker(file_path, MARKER_HOUR, False)
                lines = [line for line in loaded_data.split('\n') if line.strip() != ""]    
                all_minutes = []
                all_values = []
                for line in lines:
                    minute, value = map(float, line.split('m:'))
                    all_minutes.append(minute)
                    all_values.append(value)
                file_name, color = os.path.splitext(file_path) 
                if os.path.basename(file_name).startswith("Dogefuzz"):
                    plt.plot(all_minutes, all_values, linestyle=next(mainlinestyles), label=os.path.basename(file_name),color=color[1:], linewidth=2.9)
                else:
                    plt.plot(all_minutes, all_values, linestyle=next(linestyles), label=os.path.basename(file_name),color=color[1:], linewidth=2.9)
        else:
            print("Invalid directory path.")
            return
        
        mplcursors.cursor(hover=True).connect("add", lambda sel: sel.annotation.set_text(f"Bugs={sel.target[1]:.2f}"))
        plt.legend(loc='lower right',  bbox_to_anchor=(0.95, 0.1), ncol=2) 
        plt.xlabel('Time (min.)')
        plt.ylabel('Total # of Bugs found')
        plt.ylim(0, 82)  # Adjust the upper bound as needed
        plt.grid(True)
        plt.show()
        
    def plot_smartian_b2_instruction_coverage(self, results_folder: str): 
        if os.path.isdir(results_folder):
            file_list = [os.path.join(results_folder, file) for file in os.listdir(results_folder) if os.path.isfile(os.path.join(results_folder, file))]

            for file_path in file_list:
                loaded_data = self._read_data_after_marker(file_path, "00m: 0.0", True)
                lines = [line for line in loaded_data.split('\n') if line.strip() != ""]
                all_minutes = []
                all_values = []
                for line in lines:
                    minute, value = map(float, line.split('m:'))
                    all_minutes.append(minute)
                    all_values.append(value)
                    
                file_name, color = os.path.splitext(file_path) 
                if os.path.basename(file_name).startswith("Dogefuzz"):
                    plt.plot(all_minutes, all_values, linestyle=next(mainlinestyles), label=os.path.basename(file_name),color=color[1:], linewidth=2.9)
                else:
                    plt.plot(all_minutes, all_values, linestyle=next(linestyles), label=os.path.basename(file_name),color=color[1:], linewidth=2.9)                

        else:
            print("Invalid directory path.")
            return

        mplcursors.cursor(hover=True).connect("add", lambda sel: sel.annotation.set_text(f"Cov={sel.target[1]:.2f}"))                
        plt.legend(loc='lower right',  bbox_to_anchor=(0.9, 0.1), ncol=2)         
        plt.xlabel('Time (min.)')
        plt.ylabel('Instruction Coverage')
        plt.grid(True)
        plt.show()
        
    def plot_smartian_b2_instruction_coverage_avg(self, results_folder: str): 
        if os.path.isdir(results_folder):
            file_list = [os.path.join(results_folder, file) for file in os.listdir(results_folder) if os.path.isfile(os.path.join(results_folder, file))]

            sum_values = []
            for file_path in file_list:
                loaded_data = self._read_data_after_marker(file_path, "00m: 0.0", True)
                lines = [line for line in loaded_data.split('\n') if line.strip() != ""]
                all_minutes = []
                all_values = []
                for line in lines:
                    minute, value = map(float, line.split('m:'))
                    all_minutes.append(minute)
                    all_values.append(value)
                sum_values.append(all_values)
                
            averages = [sum(row) / len(row) for row in zip(*sum_values)]
            means = [np.median(row) for row in zip(*sum_values)]
            plt.plot(all_minutes, all_values, linestyle=next(linestyles), label=os.path.basename(file_path), linewidth=2.5)
            for i, avg in enumerate(averages, start=0):
                print(f"{int(all_minutes[i]):02}m: {avg}")
        else:
            print("Invalid directory path.")
            return
        
        mplcursors.cursor(hover=True).connect("add", lambda sel: sel.annotation.set_text(f"Cov={sel.target[1]:.2f}"))
        plt.legend(loc='upper center', bbox_to_anchor=(0.5, 1.15), ncol=2) 
        plt.xlabel('Time (min.)')
        plt.ylabel('Instruction Coverage')
        plt.grid(True)
        plt.show()        

    def plot_max_coverage_boxplot(self,results_folder: str, inputs_file: str):

        self._input_service.extract_inputs(inputs_file)
        contracts = self._contract_service.list_contracts_from_contract_list(True)
        self._result_service.extract_results(results_folder)
        (average_blackbox, average_greybox, average_directed_greybox), _ = self._output_service.get_max_coverage_result(contracts)

        data = [average_blackbox, average_greybox, average_directed_greybox]


        print("Dogefuzz-B " + str(sum(average_blackbox) / len(average_blackbox)))
        print("Dogefuzz-G " + str(sum(average_greybox) / len(average_greybox)))
        print("Dogefuzz-DG " + str(sum(average_directed_greybox) / len(average_directed_greybox)))

        labels = ['Dogefuzz-B', 'Dogefuzz-G', 'Dogefuzz-DG']
        
        plt.figure(figsize=(8, 6))
        boxplot = plt.boxplot(data, patch_artist=True)

        colors = ['firebrick', 'slateblue', 'seagreen']
        for patch, color, label in zip(boxplot['boxes'], colors, labels):
            patch.set_facecolor(color)
            patch.set_label(label)
        
        plt.xlabel('Fuzzing strategy')
        plt.ylabel('Code Coverage (%)')
        plt.ylim(0, 100)  # Adjust the upper bound as needed
        plt.title('Code Coverage by fuzzing strategy')
        mplcursors.cursor(hover=True).connect("add", lambda sel: sel.annotation.set_text(f"Cov={sel.target[1]:.2f}"))
        
        # Add legend
        plt.legend(loc='upper right')

        plt.grid(True)
        plt.show()

    def plot_max_coverage_bar(self,results_folder: str, inputs_file: str):

        self._input_service.extract_inputs(inputs_file)
        contracts = self._contract_service.list_contracts_from_contract_list(True)
        self._result_service.extract_results(results_folder)
        _, (average_blackbox, average_greybox, average_directed_greybox) = self._output_service.get_max_coverage_result(contracts)

        methods = ['']
        bar_width = 0.25
        index = range(len(methods))

        plt.bar(index, average_blackbox, bar_width, label='Dogefuzz-B', color='firebrick')
        plt.bar([i + bar_width for i in index], average_greybox, bar_width, label='Dogefuzz-G', color='slateblue')
        plt.bar([i + bar_width * 2 for i in index], average_directed_greybox, bar_width, label='Dogefuzz-DG', color='seagreen')

        plt.xlabel('Fuzzing strategy')
        plt.ylabel('Code Coverage (%)')
        plt.title('Code Coverage by fuzzing strategy')
        plt.xticks([])
        plt.yticks(range(0, 101, 10))
        plt.gca().yaxis.set_major_formatter(mtick.PercentFormatter(100))
        mplcursors.cursor(hover=True).connect("add", lambda sel: sel.annotation.set_text(f"Cov={sel.target[1]:.2f}"))

        plt.legend()
        plt.tight_layout()

        plt.show()
