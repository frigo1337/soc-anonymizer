
# 🔒 SOC Incident Anonymizer

Anonymize sensitive information in SOC incident reports before sharing with an LLM and de-anonymize the results for final reporting.

### What is this?

This ~~is~~ *will become* a small, standalone Windows application built in Python. Its purpose is to help SOC analysts and incident responders protect sensitive data when using LLMs or other potentially *"leaky"* tools to write reports. It works by replacing private details like IP addresses, usernames, and hostnames with generic, persistent tags.

### 🔩 Key Features

- **Persistent Mappings:** Consistent anonymization and de-anonymization within the same session. An IP address will always be replaced by the same tag (e.g., `{ip1}`).
    
- **Automated Detection:** Automatically finds and tags common sensitive data, including:
    
    - IP addresses (IPv4 & IPv6)
    - Email addresses
    - Usernames found in common file paths (e.g., `C:\Users\Username`)
    - Hostnames based on a configurable prefix (e.g., `DESKTOP-` or `SRV-`)
    - A company name
        
- **Custom Anonymization:** Define your own custom literal strings and tags for anything else you need to mask.
  
- **Simple GUI:** A straightforward interface with a side-by-side view for input and output.

- **DARK MODE** 🌚🌚🌚 *plus super secret 1337 mode for all you trve cybercrimefighters with rizz/ricing*

    
### How it Works

1. **Paste:** Copy and paste your raw incident log or report text into the **Input** pane.
    
2. **Anonymize:** Click the `Anonymize →` button. The application replaces all detected sensitive data with anonymized tags in the **Output** pane.
    
3. **Use:** Copy the anonymized text and paste it into your LLM for analysis or summarization.
    
4. **De-anonymize:** When the LLM provides its output, paste it back into the **Input** pane and click `← De-anonymize` to restore the original sensitive values in the output.

### To-Do *Soon*™️:
- Pack it into an .exe that can be run on a Windows Sandbox without any dependencies


### 🤝 Contributing

Suggestions for improvements and bug reports are welcome! Feel free to open an issue or submit a pull request.