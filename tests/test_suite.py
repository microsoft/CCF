import e2e_logging
import reconfiguration
import recovery

# For now, these are hardcoded
tests = [
    reconfiguration.test_add_node,
    reconfiguration.test_add_node_from_backup,
    reconfiguration.test_add_as_many_pending_nodes,
    reconfiguration.test_add_node_untrusted_code,
    reconfiguration.test_retire_node,
    e2e_logging.test,
    e2e_logging.test_update_lua,
    recovery.test,
]

#
# Test functions should only make assumptions on the number of nodes in the network
# or the application it is running.
#
# Test functions are expected to be in the following format:
#
# def test(network, args):
#     LOG.info("<Test Description>")
#
#     # Test logic, e.g. issuing transaction or adding a node
#
#     return network
