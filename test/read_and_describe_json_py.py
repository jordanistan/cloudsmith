import json

def flatten_dict(d, separator='_', prefix=''):
    items = []
    for k, v in d.items():
        new_key = prefix + separator + k if prefix else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, separator, new_key).items())
        elif isinstance(v, list):
            for i, elem in enumerate(v):
                if isinstance(elem, dict):
                    items.extend(flatten_dict(elem, separator, new_key + separator + str(i)).items())
                else:
                    items.append((new_key + separator + str(i), elem))
        else:
            items.append((new_key, v))
    return dict(items)


def process_json_file(file_name, keys_to_extract):
    # Open the file as JSON
    with open(file_name, 'r') as file:
        data = json.load(file)

    # Flatten the JSON and store it in a list
    flat_dicts = [flatten_dict(item) for item in data['actions']]

    # Initialize a list to store the extracted information
    extracted_info = []

    # Loop over the flattened dictionaries
    for dictionary in flat_dicts:
        # Initialize a dictionary to store the extracted key-value pairs
        extracted_dict = {}

        # Loop over the keys to extract
        for key in keys_to_extract:
            # If the key is in the dictionary, add it to the extracted_dict
            if key in dictionary:
                extracted_dict[key] = dictionary[key]

        # If any key-value pairs were extracted, add the dictionary to the extracted_info list
        if extracted_dict:
            extracted_info.append(extracted_dict)

    # Return the extracted information and the flattened dictionaries
    return extracted_info

def write_info_to_file(file_name, info):
    # Open the file
    with open(file_name, 'w') as file:
        # Loop over the dictionaries in the info list
        for i, dictionary in enumerate(info, start=1):
            for key, value in dictionary.items():
                # Write the key-value pair in the requested format
                file.write(f"package{i} have {key}: {value}\n")
            # Write three newlines after each dictionary
            file.write('\n\n\n')