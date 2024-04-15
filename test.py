import numpy as np

def convert_string_to_numpy(data: str):
    # Convert string to binary representation
    binary_string = ''.join(format(ord(char), '08b') for char in data)
    # Convert binary string to NumPy array of 1's and 0's
    binary_array = np.array([int(bit) for bit in binary_string])
    return binary_array


def convert_numpy_to_string(data):

    binary_string = ''.join(map(str, data))
    output_string = ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))
    return output_string


# Input string
input_string = "hello world"

binary_string = convert_string_to_numpy(input_string)
new_string = convert_numpy_to_string(binary_string)
print(new_string)

# Convert string to binary representation
binary_string = ''.join(format(ord(char), '08b') for char in input_string)

# Convert binary string to NumPy array of 1's and 0's
binary_array = np.array([int(bit) for bit in binary_string])

print("Binary array:", binary_array)

# Convert binary array back to string
output_string = ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))

print("Output string:", output_string)
