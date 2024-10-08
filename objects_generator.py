import uuid
import stix2
import re
from utils import get_current_time, validate_pattern, apply_tlp_marking, get_valid_input, get_object_id_by_name

def generate_indicator(name: str, pattern_type: str, pattern_value: str = None, tlp_color: str = 'none') -> dict:
    try:
        current_time = get_current_time()

        # Ensure pattern_type is provided and valid
        if not pattern_type:
            raise ValueError("Pattern type is required.")

        # Allow the user to select from a list of indicator types
        indicator_type_options = [
            'anomalous-activity', 'anonymization', 'benign', 'compromised', 
            'malicious-activity', 'attribution', 'unknown'
        ]
        indicator_type = get_valid_input(
            "Select an indicator type (number or name): ",
            indicator_type_options
        )

        # Validate IPv4 address input if pattern_type is 'ipv4-addr'
        if pattern_type == 'ipv4-addr':
            if not pattern_value or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", pattern_value):
                raise ValueError("Invalid IPv4 address format.")
            if not all(0 <= int(segment) <= 255 for segment in pattern_value.split('.')):
                raise ValueError("IPv4 address segments must be in the range of 0-255.")
        elif pattern_type == 'domain-name':
            # Validate domain names with allowed suffixes
            if pattern_value and not pattern_value.endswith(('.com', '.net', '.org', '.io')):
                raise ValueError(f"Invalid domain name for pattern_type {pattern_type}.")
        elif pattern_value is None:
            # Generate pattern if no value is provided
            pattern_value = validate_pattern(pattern_type)

        # Create the STIX pattern
        stix_pattern = f"[{pattern_type}:value = '{pattern_value}']"
        print(f"STIX Pattern used: {stix_pattern}")

        # Create the Indicator object with the selected indicator type
        indicator = stix2.Indicator(
            id=f"indicator--{uuid.uuid4()}",
            name=name,
            created=current_time,
            modified=current_time,
            pattern=stix_pattern,
            pattern_type='stix',
            indicator_types=[indicator_type],
            spec_version="2.1"
        )

        # Apply TLP marking to 'object_marking_refs' only
        if tlp_color != 'none':
            return apply_tlp_marking(indicator, tlp_color)

        return indicator

    except Exception as e:
        print(f"Error generating indicator: {e}")
        return None

def generate_identity_with_consent(name: str, tlp_color: str = 'none') -> dict:
    try:
        current_time = get_current_time()

        # Define the AIS consent options
        ais_consent_options = [
            'ais-consent-none',
            'ais-consent-usg',
            'ais-consent-everyone-cisa-proprietary',
            'ais-consent-everyone'
        ]

        # Define the identity_class options
        identity_class_options = [
            'individual', 'group', 'system', 'organization', 'class', 'unspecified'
        ]

        # Prompt the user to select from the AIS consent options
        consent_label = get_valid_input(
            "Select a consent label (number or name): ",
            ais_consent_options
        )

        # Prompt the user to select an identity class
        identity_class = get_valid_input(
            "Select an identity class (number or name): ",
            identity_class_options
        )

        # Get the description from the user first
        description = input("Enter a description for the identity (optional, press Enter to skip): ").strip()

        # Create the Identity object with consent label and identity class
        identity = stix2.Identity(
            id=f"identity--{uuid.uuid4()}",
            created=current_time,
            modified=current_time,
            name=name,
            identity_class=identity_class,  # Assign the selected identity class
            labels=[consent_label],  # Assign the selected AIS consent label
            description=description if description else None,  # Set description if provided
            spec_version="2.1"
        )

        # Apply TLP marking to 'object_marking_refs' only
        if tlp_color != 'none':
            identity = apply_tlp_marking(identity, tlp_color)

        return identity
    except Exception as e:
        print(f"Error generating identity: {e}")
        return None

def generate_malware(name: str, is_family: bool, tlp_color: str = 'none') -> dict:
    try:
        current_time = get_current_time()

        # Define malware types
        malware_types_options = [
            'adware', 'backdoor', 'bot', 'bootkit', 'ddos', 'downloader', 'dropper', 'exploit-kit', 
            'keylogger', 'ransomware', 'remote-access-trojan', 'resource-exploitation', 
            'rogue-security-software', 'rootkit', 'screen-capture', 'spyware', 'trojan', 'unknown', 
            'virus', 'webshell', 'wiper', 'worm'
        ]

        # Prompt user to select a malware type
        malware_type = get_valid_input(
            "Select a malware type (number or name): ",
            malware_types_options
        )

        malware = stix2.Malware(
            id=f"malware--{uuid.uuid4()}",
            created=current_time,
            modified=current_time,
            name=name,
            is_family=is_family,
            malware_types=[malware_type],  # Assign the selected malware type
            labels=["malware"],
            spec_version="2.1"
        )

        # Apply TLP marking to 'object_marking_refs' only
        if tlp_color != 'none':
            malware = apply_tlp_marking(malware, tlp_color)

        return malware
    except Exception as e:
        print(f"Error generating malware: {e}")
        return None

def generate_threat_actor(name: str, description: str, tlp_color: str = 'none') -> dict:
    try:
        current_time = get_current_time()

        # Options for user input
        threat_actor_types = ['activist', 'competitor', 'crime-syndicate', 'criminal', 'hacker', 
                              'insider-accidental', 'insider-disgruntled', 'nation-state', 
                              'sensationalist', 'spy', 'terrorist', 'unknown']
        
        roles = ['agent', 'director', 'independent', 'infrastructure-architect', 'infrastructure-operator', 'malware-author', 'sponsor']
        
        sophistication_options = ['none', 'minimal', 'intermediate', 'advanced', 'expert', 'innovator', 'strategic']

        # Get user input for the properties
        threat_actor_type = get_valid_input("Select threat actor type (number or name): ", threat_actor_types)
        role = get_valid_input("Select role (number or name): ", roles)
        sophistication = get_valid_input("Select sophistication level (number or name): ", sophistication_options)

        # Optional aliases and goals properties
        aliases = input("Enter aliases for the Threat Actor (optional, press Enter to skip): ").strip().split(",")
        aliases = [alias.strip() for alias in aliases if alias]  # Ensure clean list
        goals = input("Enter the goals for the Threat Actor (optional, press Enter to skip): ").strip()
        description = input("Enter a description for the Threat Actor (optional, press Enter to skip): ").strip()


        # Create the Threat Actor object
        threat_actor = stix2.ThreatActor(
            id=f"threat-actor--{uuid.uuid4()}",
            created=current_time,
            modified=current_time,
            name=name,
            description=description,
            roles=[role],
            threat_actor_types=[threat_actor_type],
            sophistication=sophistication,
            spec_version="2.1"
        )

        # Add description, aliases, and goals if provided
        if description:
            threat_actor = threat_actor.new_version(description=description)
        if aliases:
            threat_actor = threat_actor.new_version(aliases=aliases)
        if goals:
            threat_actor = threat_actor.new_version(goals=[goals])

        # Apply TLP marking if specified
        if tlp_color != 'none':
            return apply_tlp_marking(threat_actor, tlp_color)

        return threat_actor

    except Exception as e:
        print(f"Error generating Threat Actor: {e}")
        return None

def generate_vulnerability(name: str, tlp_color: str = 'none') -> dict:
    try:
        current_time = get_current_time()

        # Optional description
        description = input("Enter a description for the Vulnerability (optional, press Enter to skip): ").strip()

        # Ask if the user has external references
        external_references = []
        has_external_references = get_valid_input("Do you have any external references? (yes/no): ", ['yes', 'no'])

        if has_external_references == 'yes':
            print("The source_name is automatically set to 'cve'.")
            external_reference_external_id = input("Enter the external ID (must follow CVE-year-xxxx format): ").strip().upper()

            if not re.match(r"CVE-\d{4}-\d{4,7}", external_reference_external_id):
                print("Invalid format. Please enter a valid CVE ID (e.g., CVE-2021-1234).")
            else:
                external_references.append({
                    "source_name": "cve",
                    "external_id": external_reference_external_id
                })

        # Create the Vulnerability object with type set
        vulnerability = stix2.Vulnerability(
            id=f"vulnerability--{uuid.uuid4()}",
            created=current_time,
            modified=current_time,
            name=name,
            spec_version="2.1",
        )

        # Add description if provided
        if description:
            vulnerability = vulnerability.new_version(description=description)

        # Add external references if provided
        if external_references:
            vulnerability = vulnerability.new_version(external_references=external_references)

        # Apply TLP marking if specified
        if tlp_color != 'none':
            return apply_tlp_marking(vulnerability, tlp_color)

        return vulnerability

    except Exception as e:
        print(f"Error generating Vulnerability: {e}")
        return None

def generate_attack_pattern(name: str, tlp_color: str = 'none') -> dict:
    try:
        current_time = get_current_time()

        # Optional description
        description = input("Enter a description for the Attack Pattern (optional, press Enter to skip): ").strip()

        # Ask if the user has external references
        external_references = []
        has_external_references = get_valid_input("Do you have any external references? (yes/no): ", ['yes', 'no'])

        if has_external_references == 'yes':
            print("The source_name is automatically set to 'capec'.")
            external_reference_external_id = input("Enter the external ID (must follow CAPEC-xxxx format): ").strip().upper()

            if not re.match(r"CAPEC-\d{1,4}", external_reference_external_id):
                print("Invalid format. Please enter a valid CAPEC ID (e.g., CAPEC-1234).")
            else:
                external_references.append({
                    "source_name": "capec",
                    "external_id": external_reference_external_id
                })

        # Create the Attack Pattern object with type set
        attack_pattern = stix2.AttackPattern(
            id=f"attack-pattern--{uuid.uuid4()}",
            created=current_time,
            modified=current_time,
            name=name,
            spec_version="2.1"
        )

        # Add description if provided
        if description:
            attack_pattern = attack_pattern.new_version(description=description)

        # Add external references if provided
        if external_references:
            attack_pattern = attack_pattern.new_version(external_references=external_references)

        # Apply TLP marking if specified
        if tlp_color != 'none':
            return apply_tlp_marking(attack_pattern, tlp_color)

        return attack_pattern

    except Exception as e:
        print(f"Error generating Attack Pattern: {e}")
        return None

def generate_course_of_action(name: str, tlp_color: str = 'none') -> dict:
    try:
        current_time = get_current_time()

        # Optional description
        description = input("Enter a description for the Course of Action (optional, press Enter to skip): ").strip()

        # Optional action_reference
        action_reference = None
        has_action_reference = get_valid_input("Do you want to specify an action reference? (yes/no): ", ['yes', 'no'])
        if has_action_reference == 'yes':
            print("The source_name is automatically set to 'internet'.")
            domain_name = input("Enter a valid domain name (e.g., example.com): ").strip().lower()

            if not re.match(r"^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$", domain_name):
                print("Invalid domain name format. Please enter a valid domain (e.g., example.com).")
            else:
                action_reference = {
                    "source_name": "internet",
                    "url": f"http://{domain_name}"
                }

        # Create the Course of Action object with type set
        course_of_action = stix2.CourseOfAction(
            id=f"course-of-action--{uuid.uuid4()}",
            created=current_time,
            modified=current_time,
            name=name,
            spec_version="2.1",
            type="course-of-action"
        )

        # Add description if provided
        if description:
            course_of_action = course_of_action.new_version(description=description)

        # Add action_reference if provided
        if action_reference:
            course_of_action = course_of_action.new_version(external_references=[action_reference])

        # Apply TLP marking if specified
        if tlp_color != 'none':
            return apply_tlp_marking(course_of_action, tlp_color)

        return course_of_action

    except Exception as e:
        print(f"Error generating Course of Action: {e}")
        return None

def generate_sighting(stored_objects: list, tlp_color: str = 'none') -> dict:
    try:
        current_time = get_current_time()

        # Filter and display available STIX objects for sighting (e.g., indicators or malware)
        available_objects = [obj for obj in stored_objects if obj['object']['type'] in ['indicator', 'malware']]
        if not available_objects:
            print("No available objects (e.g., indicators, malware) to create a sighting for. Please create those objects first.")
            return None

        # Display available objects for the user to choose from
        print("Available objects for sighting:")
        for i, obj in enumerate(available_objects):
            print(f"{i+1}. {obj['name']} (Type: {obj['object']['type']})")

        # Let the user select the object for sighting
        selected_index = int(get_valid_input("Select the object to create a sighting for (enter the number): ", [str(i+1) for i in range(len(available_objects))])) - 1
        sighting_of_ref = available_objects[selected_index]['object']['id']

        # Optional Where Sighted Refs (who or what saw it)
        where_sighted_refs = []
        has_where_sighted = get_valid_input("Do you want to specify where the sighting occurred? (yes/no): ", ['yes', 'no'])
        if has_where_sighted == 'yes':
            available_identities = [obj for obj in stored_objects if obj['object']['type'] == 'identity']
            if available_identities:
                print("Available identities for where the sighting occurred:")
                for i, identity in enumerate(available_identities):
                    print(f"{i+1}. {identity['name']} (Type: {identity['object']['type']})")

                selected_identity = int(get_valid_input("Select the identity where the sighting occurred (enter the number): ", [str(i+1) for i in range(len(available_identities))])) - 1
                where_sighted_refs.append(available_identities[selected_identity]['object']['id'])

        # Optional Observed Data Refs (related observed data)
        observed_data_refs = []
        has_observed_data = get_valid_input("Do you have any observed data references? (yes/no): ", ['yes', 'no'])
        if has_observed_data == 'yes':
            available_observed_data = [obj for obj in stored_objects if obj['object']['type'] == 'observed-data']
            if available_observed_data:
                print("Available observed data:")
                for i, observed_data in enumerate(available_observed_data):
                    print(f"{i+1}. {observed_data['name']}")

                selected_observed = int(get_valid_input("Select observed data (enter the number): ", [str(i+1) for i in range(len(available_observed_data))])) - 1
                observed_data_refs.append(available_observed_data[selected_observed]['object']['id'])

        # Optional first_seen and last_seen timestamps
        use_current_time = get_valid_input("Do you want to use the current date and time for 'first_seen' and 'last_seen'? (yes/no): ", ['yes', 'no'])
        if use_current_time == 'yes':
            first_seen = current_time
            last_seen = current_time
        else:
            first_seen = input("Enter the first seen timestamp (e.g., 2022-01-01T00:00:00.000Z, optional): ").strip()
            last_seen = input("Enter the last seen timestamp (e.g., 2022-01-01T00:00:00.000Z, optional): ").strip()

        # Optional count and summary
        count = input("Enter the number of times this sighting was seen (default is 1): ").strip()
        count = int(count) if count else 1
        summary = get_valid_input("Is this a summary sighting? (yes/no): ", ['yes', 'no'])
        summary = summary == 'yes'

        # Create the Sighting object
        sighting = stix2.Sighting(
            id=f"sighting--{uuid.uuid4()}",
            created=current_time,
            modified=current_time,
            sighting_of_ref=sighting_of_ref,
            spec_version="2.1",
            type="sighting",
            where_sighted_refs=where_sighted_refs or None,  # Add only if provided
            observed_data_refs=observed_data_refs or None,  # Add only if provided
            first_seen=first_seen if first_seen else None,
            last_seen=last_seen if last_seen else None,
            count=count,
            summary=summary
        )

        # Apply TLP marking if specified
        if tlp_color != 'none':
            return apply_tlp_marking(sighting, tlp_color)

        return sighting

    except Exception as e:
        print(f"Error generating Sighting: {e}")
        return None

def generate_relationship_by_names(relationship_type: str, source_name: str, target_name: str) -> dict:
    try:
        current_time = get_current_time()

        source_ref = get_object_id_by_name(source_name)
        target_ref = get_object_id_by_name(target_name)

        if source_ref and target_ref:
            relationship = stix2.Relationship(
                id=f"relationship--{uuid.uuid4()}",
                created=current_time,
                modified=current_time,
                relationship_type=relationship_type,
                source_ref=source_ref,
                target_ref=target_ref,
                spec_version="2.1"
            )
            return relationship
        else:
            print(f"Error: One or both objects not found. Source: {source_name}, Target: {target_name}")
            return None
    except Exception as e:
        print(f"Error generating relationship: {e}")
        return None
