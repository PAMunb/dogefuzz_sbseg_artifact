def map_vulnerability_to_dogefuzz_standard(vulnerability: str) -> str:
    if vulnerability == 'delegatecall_dangerous':
        return 'delegate'
    elif vulnerability == 'exception_disorder':
        return 'exception-disorder'
    elif vulnerability == 'gasless_send':
        return 'gasless-send'
    elif vulnerability == 'numberdependency':
        return 'number-dependency'
    elif vulnerability == 'reentrancy':
        return 'reentrancy'
    elif vulnerability == 'timedependency':
        return 'timestamp-dependency'
    else:
        return None


def map_vulnerability_to_smartian_standard(vulnerability: str) -> str:
    if vulnerability == 'delegatecall_dangerous':
        return 'ME'
    elif vulnerability == 'exception_disorder':
        return 'ME'
    elif vulnerability == 'gasless_send':
        return 'ME'
    elif vulnerability == 'numberdependency':
        return 'BD'
    elif vulnerability == 'reentrancy':
        return 'RE'
    elif vulnerability == 'timedependency':
        return 'BD'
    else:
        return None


def map_weakness_to_smartian_standard(vulnerability: str) -> str:
    if vulnerability == 'delegate':
        return 'ME'
    elif vulnerability == 'exception-disorder':
        return 'ME'
    elif vulnerability == 'gasless-send':
        return 'ME'
    elif vulnerability == 'number-dependency':
        return 'BD'
    elif vulnerability == 'reentrancy':
        return 'RE'
    elif vulnerability == 'timestamp-dependency':
        return 'BD'
    else:
        return None

def map_vulnerability_smartian_to_long_name(vulnerability: str) -> str:
    if vulnerability == 'ME':
        return 'MishandledException'
    elif vulnerability == 'RE':
        return 'Reentrancy'
    elif vulnerability == 'BD':
        return 'BlockstateDependency'
    else:
        return None


def is_smartian_type(smartian_type: str,vulnerability: str ) -> bool:
    if smartian_type == 'ME':
        return True if vulnerability in ['delegate', 'exception-disorder', 'gasless-send'] else False
    elif smartian_type == 'RE':
        return True if vulnerability in ['reentrancy'] else False
    elif smartian_type == 'BD':
        return True if vulnerability in ['number-dependency', 'timestamp-dependency'] else False
    else:
        return False
