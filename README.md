# Mini Miner

An experiment in mining Bitcoin on MicroPython-enabled devices.

This is a fascinating exploration of MicroPython’s flexibility and the capabilities of constrained hardware. This project offers a basic way to understand blockchain mechanics, hashing algorithms, and the challenges of implementing them on minimal devices.

## Background

This project was born from the idea of pushing the limits of what NumWorks can do by attempting to mine Bitcoin on it.

NumWorks is an open-source, minimalist calculator crafted for learning and exploration. It includes a reduced-spec implementation of MicroPython, complete with a functional math module. Inspired by the array of unconventional devices used to calculate Bitcoin hashes, I thought—why not my calculator? Anyway, I hadn't used this calculator in a couple of years.

Once I got the mining simulation functional on NumWorks, I also explored modifications and porting it to other platforms.

### Networking Note

My calculator did not have any way to interface with the internet, even when connected to a computer. Networking implementation appears to be platform-specific for many MicroPython controllers. However, with the standard `requests` library, implementing networking functionality would be feasible. While not trivial, it would be easy enough to incorporate a mining protocol for compatible platforms.

For this test, I have hardcoded the genesis block with a lower difficulty for demonstration purposes.

## Implementation Notes

- **Simulation Focus**: This project simulates the Bitcoin mining process rather than performing real-world mining. The difficulty is intentionally reduced for demonstration purposes.

- **Time Function Variations**: MicroPython implementations handle time differently. For instance, NumWorks uses `time.monotonic`, while some MicroPython often uses `ticks_ns` or `ticks_us`. To run this on CPython (the normal Python on your laptop), you would need to use `time.time`. To address this, the script implements a custom `_time` function. If you encounter time-related errors, ensure `_time` is adapted to your environment.

- **Hashrate Display**: Due to the limited hardware of most MicroPython controllers, the hashrate is low. To make the output manageable, the script prints the hashrate every 100 hashes instead of after each individual hash.

- **Data Type Constraints**: Some MicroPython implementations lack certain data types, such as `bytearray`, necessitating the use of less efficient alternatives like integer lists to represent bytes. This workaround impacts performance but ensures compatibility.

### Key Features

- Functional SHA-256 hashing implemented in MicroPython.
- Mining simulation with a lower difficulty target for demonstration purposes.
- Adaptive support for different MicroPython environments.

## How to Run the Script

1. **Setup**: Ensure your MicroPython device is equipped with MicroPython support.
2. **Load the Script**: Copy the Python script into the MicroPython editor of your device.
3. **Execute**: Run the script. It will first perform SHA-256 tests to verify correctness, then initiate the mining simulation.

### Expected Output

- **SHA-256 Tests**: The script validates its hashing implementation through several test cases.
- **Mining Simulation**: The script processes the genesis block header, searching for a nonce that satisfies the lower difficulty target.
- **Hashrate**: Hashrate metrics are displayed every 100 hashes, providing an idea of processing speed.

## Limitations

- **Performance**: This goes without saying—Bitcoin mining is computationally demanding and it will take you an infinite amount of time to mine any Bitcoin. This script serves purely as an educational tool and does not perform practical mining.
- **Hardware Constraints**: Due to the limitations of MicroPython devices and its reduced feature set, the implementation prioritizes compatibility and functionality over efficiency.
