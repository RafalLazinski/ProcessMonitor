import argparse
import psutil
from typing import Dict, Any, Optional


def get_process_details(pid: int) -> Optional[Dict[str, Any]]:
    """
    Fetches detailed information about a process given its PID.

    Args:
        pid (int): Process ID of the target process

    Returns:
        Optional[Dict[str, Any]]: Dictionary containing process details or None if process not found

    Example:
        >>> details = get_process_details(1234)
        >>> if details:
        >>>     print(details)
    """
    try:
        process = psutil.Process(pid)
        process_info = {
            'pid': process.pid,
            'name': process.name(),
            'exe': process.exe(),
            'cmdline': process.cmdline(),
            'parent_pid': process.ppid(),
            'status': process.status(),
            'cwd': process.cwd()
        }

        return process_info

    except psutil.NoSuchProcess:
        print(f"Process with PID {pid} not found")
        return None
    except psutil.AccessDenied:
        print(f"Access denied to process with PID {pid}")
        return None
    except Exception as e:
        print(f"Error retrieving process details: {e}")
        return None


def get_child_processes_details(pid: int, recursive: bool = True) -> list[Dict[str, Any]]:
    """
    Gets detailed information about all child processes of a given process ID.

    Args:
        pid (int): Process ID of the parent process
        recursive (bool): If True, includes grandchildren and deeper descendants

    Returns:
        list[Dict[str, Any]]: List of dictionaries containing process details for each child
    """
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=recursive)

        child_details = []
        for child in children:
            details = get_process_details(child.pid)
            if details:
                child_details.append(details)

        return child_details

    except psutil.NoSuchProcess:
        print(f"Process with PID {pid} not found")
        return []
    except psutil.AccessDenied:
        print(f"Access denied to process with PID {pid}")
        return []
    except Exception as e:
        print(f"Error retrieving child processes: {e}")
        return []

def print_process_details(process_details: Dict[str, Any]):
    if process_details:
        print("Process Details:")
        for key, value in process_details.items():
            print(f"{key}: {value}")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Process information retrieval tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --pid 1234                     # Show details for process with PID 1234
  %(prog)s --pid 1234 --children          # Show details for process 1234 and its children
""")

    parser.add_argument('--pid', type=int, help='Process ID to query', required=True)
    parser.add_argument('--children', action='store_true',
                        help='Include child processes in the output')

    return parser.parse_args()


def main():
    args = parse_args()
    parent_pid = args.pid

    parent_process_details = get_process_details(parent_pid)
    print_process_details(parent_process_details)

    if args.children:
        children_details = get_child_processes_details(parent_pid)
        if len(children_details) == 0:
            print("No child processes found")
        else:
            print("\nChild processes:")
            for children_detail in children_details:
                print("\n")
                print_process_details(children_detail)

if __name__ == "__main__":
    main()
