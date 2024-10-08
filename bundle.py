import stix2
import os

def create_bundle(objects: list) -> stix2.Bundle:
    try:
        # Validate that all objects have the correct structure
        stix_objects = [obj['object'] for obj in objects if 'object' in obj]

        # Ensure we have valid objects to bundle
        if not stix_objects:
            raise ValueError("No valid STIX objects found for bundling.")

        # Create the STIX Bundle with the extracted objects
        return stix2.Bundle(objects=stix_objects)
    except Exception as e:
        print(f"Error creating STIX bundle: {e}")
        return None

def save_bundle_to_file(bundle: stix2.Bundle, file_name: str = 'stix_bundle.json', save_dir: str = None):
    try:
        if bundle is None:
            raise ValueError("Cannot save an empty bundle.")
        
        # If no directory is provided, use the current directory
        if not save_dir:
            save_dir = os.getcwd()

        # Ensure directory exists
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        # Create full path
        full_path = os.path.join(save_dir, file_name)
        
        with open(full_path, 'w') as f:
            f.write(bundle.serialize(indent=4))
        print(f"STIX Bundle saved to {full_path}")
    except Exception as e:
        print(f"Error saving STIX bundle to file: {e}")
