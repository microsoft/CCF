import experiments

test_directory = experiments.create_test_directory()
remote_servers = [
    "172.23.0.4:8000",
    "172.23.0.7:8000",
    "172.23.0.8:8000",
    "172.23.0.9:8000",
    "172.23.0.10:8000",
]

experiments.all_tests(remote_servers, test_directory)
