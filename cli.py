from objects_generator import generate_indicator, generate_identity_with_consent, generate_malware, generate_relationship_by_names, generate_threat_actor, generate_vulnerability, generate_attack_pattern, generate_course_of_action, generate_sighting
from utils import add_object_to_store, get_valid_input, determine_valid_relationship_types, validate_pattern
from bundle import create_bundle, save_bundle_to_file
import re

def interactive_mode():
    objects = []

    while True:
        try:
            object_type = get_valid_input(
                "Enter STIX object type (number or name): ", 
                ['indicator', 'identity', 'malware', 'relationship', 'threat-actor',
                'vulnerability', 'attack-pattern', 'course-of-action', 'sighting', 'done']
            )
            if object_type == 'done':
                break

            tlp_color = get_valid_input(
                "Select TLP color (number or name): ", 
                ['white', 'green', 'amber', 'red', 'none']
            )

            if object_type == 'indicator':
                pattern_type = get_valid_input(
                    "Enter pattern type (number or name): ", 
                    ['domain-name', 'ipv4-addr', 'email-addr', 'sha256']
                )

                # Allow blank input for all patterns and generate one if blank
                pattern_value = input(f"Enter a value for {pattern_type} (leave blank to generate one): ")
                if not pattern_value:
                    pattern_value = validate_pattern(pattern_type)

                # Validate IPv4 address
                if pattern_type == 'ipv4-addr' and pattern_value:
                    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", pattern_value) or \
                        not all(0 <= int(segment) <= 255 for segment in pattern_value.split('.')):
                        print("Invalid IPv4 address. Please enter a valid one.")
                        continue

                # Validate domain names
                if pattern_type == 'domain-name' and pattern_value:
                    if not pattern_value.endswith(('.com', '.net', '.org', '.io')):
                        print("Invalid domain name. Please enter a valid one.")
                        continue

                # Validate email addresses
                if pattern_type == 'email-addr' and pattern_value:
                    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", pattern_value):
                        print("Invalid email address. Please enter a valid one.")
                        continue

                # Validate SHA256 hashes
                if pattern_type == 'sha256' and pattern_value:
                    if not re.match(r"^[a-fA-F0-9]{64}$", pattern_value):
                        print("Invalid SHA256 hash. Please enter a valid 64-character hex string.")
                        continue

                name = input("Enter a name for this indicator: ")
                indicator = generate_indicator(name, pattern_type, pattern_value, tlp_color)
                if indicator:
                    add_object_to_store(indicator, name)
                    objects.append({'name': name, 'object': indicator})

            elif object_type == 'identity':
                name = input("Enter identity name: ")
                identity = generate_identity_with_consent(name, tlp_color)
                if identity:
                    add_object_to_store(identity, name)
                    objects.append({'name': name, 'object': identity})

            elif object_type == 'malware':
                name = input("Enter malware name: ")
                is_family = get_valid_input(
                    "Is this malware a family? (yes/no): ", 
                    ['yes', 'no']
                ) == 'yes'
                malware = generate_malware(name, is_family, tlp_color)
                if malware:
                    add_object_to_store(malware, name)
                    objects.append({'name': name, 'object': malware})
            
            elif object_type == 'threat-actor':
                name = input("Enter threat actor name: ")
                threat_actor = generate_threat_actor(name, tlp_color)
                if threat_actor:
                    add_object_to_store(threat_actor, name)
                    objects.append({'name': name, 'object': threat_actor})

            elif object_type == 'vulnerability':
                name = input("Enter vulnerability name: ")
                vulnerability = generate_vulnerability(name, tlp_color)
                if vulnerability:
                    add_object_to_store(vulnerability, name)
                    objects.append({'name': name, 'object': vulnerability})

            elif object_type == 'attack-pattern':
                name = input("Enter attack pattern name: ")
                attack_pattern = generate_attack_pattern(name, tlp_color)
                if attack_pattern:
                    add_object_to_store(attack_pattern, name)
                    objects.append({'name': name, 'object': attack_pattern})

            elif object_type == 'course-of-action':
                name = input("Enter course of action name: ")
                course_of_action = generate_course_of_action(name, tlp_color)
                if course_of_action:
                    add_object_to_store(course_of_action, name)
                    objects.append({'name': name, 'object': course_of_action})

            elif object_type == 'sighting':
                sighting = generate_sighting(objects, tlp_color)
                if sighting:
                    add_object_to_store(sighting, "Sighting")
                    objects.append({'name': 'Sighting', 'object': sighting})
                    
            elif object_type == 'relationship':
                if len(objects) < 2:
                    print("You need at least two objects to create a relationship.")
                    continue

                # List available objects
                print("Available objects:")
                for i, obj in enumerate(objects):
                    # Ensure that the object has 'name' and 'object' keys before accessing them
                    if 'name' in obj and 'object' in obj and 'type' in obj['object']:
                        print(f"{i+1}. {obj['name']} ({obj['object']['type']})")
                    else:
                        print(f"{i+1}. (Unnamed or invalid object)")

                # Get user selection for source and target
                source_index = int(get_valid_input("Select source object (number): ", [str(i+1) for i in range(len(objects))])) - 1
                target_index = int(get_valid_input("Select target object (number): ", [str(i+1) for i in range(len(objects))])) - 1

                if source_index == target_index:
                    print("Source and target cannot be the same object. Try again.")
                    continue

                # Ensure valid source and target object types
                source_type = objects[source_index]['object'].get('type', None)
                target_type = objects[target_index]['object'].get('type', None)

                if not source_type or not target_type:
                    print("Invalid source or target object type.")
                    continue

                # Determine valid relationship types based on source and target object types
                relationship_type_options = determine_valid_relationship_types(source_type, target_type)

                if not relationship_type_options:
                    print(f"No valid relationship types for {source_type} and {target_type}.")
                    continue

                # Prompt user to select a valid relationship type
                relationship_type = get_valid_input(
                    "Select relationship type (number or name): ",
                    relationship_type_options
                )

                # Get the names for the selected source and target
                source_name = objects[source_index].get('name', 'Unnamed Object')
                target_name = objects[target_index].get('name', 'Unnamed Object')

                # Generate the relationship
                relationship = generate_relationship_by_names(relationship_type, source_name, target_name)
                if relationship:
                    objects.append(relationship)

        except Exception as e:
            print(f"Error in user input or object generation: {e}")

    try:
        if objects:
            file_name = input("Enter the file name for the STIX bundle (default: 'stix_bundle.json'): ") or 'stix_bundle.json'
            specify_location = get_valid_input("Do you want to specify a file location? (yes/no): ", ['yes', 'no'])
            save_dir = None
            if specify_location == 'yes':
                save_dir = input("Enter the directory to save the file (e.g., /path/to/directory): ")

            bundle = create_bundle(objects)
            save_bundle_to_file(bundle, file_name, save_dir)
        else:
            print("No objects to bundle.")
    except Exception as e:
        print(f"Error during bundle creation or saving: {e}")