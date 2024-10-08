import random
import re
from datetime import datetime

object_store = []

def get_current_time() -> str:
    """Returns the current UTC time in ISO 8601 format for STIX objects."""
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def random_string(length: int) -> str:
    """Generates a random string of lowercase letters."""
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=length))

def validate_pattern(pattern_type: str) -> str:
    """Validates and generates patterns for different STIX object types."""
    if pattern_type == 'domain-name':
        return random_string(8) + random.choice(['.com', '.net', '.co', '.io'])
    elif pattern_type == 'email-addr':
        return random_string(6) + random.choice(['@gmail.com', '@test.com', '@ymail.com', '@test.io'])
    elif pattern_type == 'ipv4-addr':
        return '.'.join(str(random.randint(1, 255)) for _ in range(4))
    elif pattern_type == 'sha256':
        return ''.join(random.choices('abcdef1234567890', k=64))
    else:
        raise ValueError("Invalid pattern type provided.")

def apply_tlp_marking(stix_object, tlp_color: str):
    TLP_COLOR_MAP = {
        'white': 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
        'green': 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
        'amber': 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b8',
        'red': 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed'
    }

    tlp_uuid = TLP_COLOR_MAP.get(tlp_color.lower())
    if tlp_uuid:
        # Ensure proper STIX identifier format
        if not re.match(r'marking-definition--[0-9a-fA-F-]{36}', tlp_uuid):
            raise ValueError(f"Invalid STIX identifier: {tlp_uuid}")
        return stix_object.new_version(object_marking_refs=[tlp_uuid])

    return stix_object


def add_object_to_store(stix_object: dict, name: str):
    """Adds an object to the store with its corresponding name and ID."""
    object_store.append({
        'name': name,
        'id': stix_object['id'],
        'object': stix_object
    })

def get_object_id_by_name(name: str) -> str:
    """Finds an object's ID by its name from the store."""
    for obj in object_store:
        if obj['name'] == name:
            return obj['id']
    return None

def get_valid_input(prompt: str, options: list) -> str:
    """Prompts the user for valid input, allows selection by name or number, and exits on too many invalid attempts."""
    attempts = 0
    numbered_options = {str(i+1): option for i, option in enumerate(options)}
    
    while attempts < 3:
        # Display numbered options for easier user input
        print("Please select an option:")
        for num, option in numbered_options.items():
            print(f"{num}. {option}")  # This prints options as a numbered list
        
        user_input = input(prompt).lower()
        
        # Validate if input is a valid number or option name
        if user_input in options:
            return user_input
        elif user_input in numbered_options:
            return numbered_options[user_input]
        else:
            print("Invalid option. Please select a valid option.")
            attempts += 1
    
    print("Too many invalid attempts. Exiting the tool.")
    exit()

def determine_valid_relationship_types(source_type: str, target_type: str) -> list:
    """Returns a list of valid relationship types based on source and target object types."""
    try:
        # Relationship rules based on source and target types
        if source_type == 'indicator':
            if target_type in ['malware', 'attack-pattern', 'campaign', 'infrastructure', 'intrusion-set', 'threat-actor', 'tool']:
                return ['indicates']
            elif target_type == 'observed-data':
                return ['based-on']

        elif source_type == 'malware':
            if target_type in ['identity', 'infrastructure', 'location', 'vulnerability']:
                return ['targets']
            elif target_type in ['attack-pattern', 'infrastructure', 'malware', 'tool']:
                return ['uses']

        elif source_type == 'identity':
            if target_type == 'location':
                return ['located-at']

        return []  # No valid relationship types found
    except Exception as e:
        print(f"Error determining relationship types: {e}")
        return []
