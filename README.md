# STIX 2.1 JSON File Generator

## Overview

The **STIX Generator** is a versatile, Python-based tool designed to facilitate the generation of **STIX 2.1 JSON** objects for use in **cyber threat intelligence (CTI)** sharing and reporting. The tool provides a user-friendly way to create complex STIX objects through interactive CLI prompts and integrates robust validation mechanisms to ensure STIX compliance. With this generator, users can craft and share detailed CTI objects that include **Indicators, Malware, Sightings, Threat Actors, and more**.

## Current Functionality

### 1. Indicator Objects:
  + Supports patterns for `domain-name`, `ipv4-addr`, `email-addr`, and `sha256`.
  + Automatic validation for input fields, with the option to generate random values if not provided.
  + Optional TLP marking support.

### 2. Identity Objects:
  + Users can define consent levels for identity objects, such as `ais-consent-none`, `ais-consent-usg`, and more.
  + Supports detailed information for creating comprehensive identity STIX objects, including identity_class values.

### 3. Malware, Vulnerability, and Threat Actor Objects:
  + Implements required fields like `type`, `spec_version`, `id`, `created`, and `modified`.
  + Optional fields include `description`, `external_references`, and other specific properties based on STIX 2.1 specifications.

### 4. Course of Action Objects:
  + Provides options for creating action references with domain validation.
  + Handles optional properties like `external_references` and description.

### 5. Attack Pattern Objects:
  + Automatically sets `source_name` for external references to capec and validates CAPEC IDs.

### 6. Sighting Objects:
  + Allows users to create sightings based on existing Indicators or Malware in the system.
  + Supports `where_sighted_refs` for specifying locations or identities where the sightings occurred.
  + Optional `timestamps`, `count`, and `summary` fields for better customization.

### Additional Functionality
  + **Object Selection Based on Existing Objects:** For objects like Sighting, users can select from previously created Indicator or Malware objects, enhancing usability and ensuring valid STIX references.
  + **UUID Management:** Automatically generates and manages UUIDs for STIX objects.
  + **Optional Auto-Timestamping:** Users can choose to use the current date and time for fields like `created`, `modified`, `first_seen`, and `last_seen`.
  + **User Input Validation:** Extensive validation for fields like domain names, IP addresses, email addresses, and SHA256 hashes.

## Technologies and Libraries Used
  + **Python 3.8+:** Core programming language used for the implementation.
  + **STIX2 Library:** Utilized for creating and validating STIX 2.1 objects.
  + **UUID Library:** For generating unique identifiers for STIX objects.
  + **re (Regular Expressions):** For input validation (e.g., validating IP addresses, domain names, and external references).
  + **Datetime:** To manage timestamps and ensure correct ISO 8601 formatting.
  + **json:** Handles JSON serialization for storing and managing STIX objects.

## How to Run the Tool

**1. Clone the Repository:**
```
git clone https://github.com/yourusername/stix-generator.git
cd stix-generator
```
**2. Install Dependencies:**
```
pip install stix2
```
**3. Run the Tool:**
```
python stix_generator.py
```
**4. Interact with the CLI:**
  + The tool will prompt you to select which STIX objects to create.
  + Choose from the options such as **Indicator**, **Malware**, **Sighting**, or **Identity**.
  + Follow the prompts to fill in the required and optional fields.

**5. Save the STIX Bundle:**
  + At the end of the session, you will have the option to save the generated STIX bundle as a JSON file.
  + Specify the file name and location, or use the default values provided.

# Future Functionality Ideas

**1. Expanded STIX Object Support:** Add support for objects like Campaign, Intrusion Set, Observed Data, and Tool to enhance the flexibility of the tool.

**2. Dynamic Relationship Support:** Add dynamic relationship outputs to support the complexities between SDOs and SROs.

**3. Predefined Object Templates:** Provide common templates for frequently created STIX objects, such as templates for known malware families, phishing campaigns, or C2 infrastructure.

**4. Integration with External Threat Databases:** Integration with databases like MITRE ATT&CK, CVE, or AlienVault OTX to pull in relevant threat data automatically.

**5. Graphical User Interface (GUI):** Develop a web-based GUI for non-technical users, allowing drag-and-drop functionality for building STIX objects and bundles.

**6. STIX Bundle Export Options:** Allow for more granular control over the STIX export options, including support for encrypted bundles and TAXII integration.

# Contributing

We welcome contributions! Please submit pull requests, issues, or feature requests through our GitHub repository.

# License

This project is licensed under the MIT License. See the LICENSE file for more details.
