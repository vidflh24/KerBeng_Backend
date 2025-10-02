import psutil
import time
from AutoPentest import APentest
from CVE import *

params = {
        "ipAddrs":"10.33.102.225"
    }

# Function to monitor CPU and memory usage during the execution of a function
#def monitor_resource_usage(func, *args, **kwargs):
def monitor_resource_usage():
    # Record start time
    start_time = time.time()
    
    # Start monitoring CPU and memory usage
    process = psutil.Process()
    cpu_usage_start = psutil.cpu_percent(interval=None)
    memory_usage_start = process.memory_info().rss / (1024 * 1024)  # Convert to MB
    
    # Execute the function
    #result = func(*args, **kwargs)
    client_code(CVE22_46169.CVE22_46169Cacti1(), params)
    
    # Record end time
    end_time = time.time()
    
    # Get CPU and memory usage after execution
    cpu_usage_end = psutil.cpu_percent(interval=None)
    memory_usage_end = process.memory_info().rss / (1024 * 1024)  # Convert to MB
    
    # Calculate differences
    total_cpu_usage = cpu_usage_end - cpu_usage_start
    total_memory_usage = memory_usage_end - memory_usage_start
    execution_time = end_time - start_time
    
    return execution_time, total_cpu_usage, total_memory_usage

# Function to run multiple iterations and record results
#def run_iterations(func, iterations=5, *args, **kwargs):
# Function to run multiple iterations and record results
def run_iterations(iterations=5):
    with open("resource_usage_results.txt", "w") as file:
        file.write("Iteration, Execution Time (s), CPU Usage Increase (%), Memory Usage Increase (MB)\n")
        file.close()

    with open("resource_usage_results.txt", "a") as file:
        for i in range(1, iterations + 1):
            execution_time, cpu_usage, memory_usage = monitor_resource_usage()
            file.write(f"{i}, {execution_time:.2f}, {cpu_usage:.2f}, {memory_usage:.2f}\n")
            print(f"Iteration {i}: Execution Time: {execution_time:.2f}s, CPU Usage Increase: {cpu_usage:.2f}%, Memory Usage Increase: {memory_usage:.2f} MB")
        file.close()

# function to iterate
def client_code(autoPentest: APentest, params) -> None:
    autoPentest.startPentest(params)
    del autoPentest

if __name__ == "__main__":
    # Run 5 iterations of monitoring the example function
    run_iterations(5)
