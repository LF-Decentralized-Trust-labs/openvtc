# Backup and Restore Configurations

The tool provides functionality to backup your profile configurations, including PGP keys, so you can transfer them to another machine or restore previous settings when needed.

## Backup Configurations

To back up the configuration for your profile, run the following command:

```bash
openvtc export settings --file ~/Downloads/openvtc-export.openvtc --passphrase MyPassphrase
```

The command will:

- Export the default profile configuration, including key materials stored in the OS’s secure storage.
- Save the encrypted backup to `~/Downloads/openvtc-export.openvtc`.
- Encrypt the backup using the passphrase provided.

**Important:** Store the backup file in a secure location for future recovery.

## Restore Configurations

To restore the backup on another machine or recover your previous setup, run the following command:

```bash
openvtc setup import --file ~/Downloads/openvtc-export.openvtc --passphrase MyPassphrase
```

The command will:

- Import the configurations from the backup file.
- Recreate the default profile (if no `--profile` option), including secured configuration stored in the OS’s secure storage.

This process is helpful in use cases, such as:

- Transferring OpenVTC configuration to a new machine.
- Recovering access after losing the original machine.
- Resetting the OpenVTC configuration.

## DID Secrets Recovery

To restore the same DID and associated secrets, use the **24-word recovery phrase** generated during the previous setup. This recovery phrase allows you to regenerate the DID secrets and an option to retain the same DID value. To do this:

1. Run the setup command:

   ```bash
   openvtc setup
   ```

   > Optionally, run the setup command with the `--profile` to setup another profile.

2. The first prompt will ask you if you would like to recover your DID secrets using the 24-word recovery phrase, select `yes`.

   ```bash
   ? Recover Secrets from 24 word recovery phrase? (y/n) › yes
   ```

3. Enter the 24-word recovery phrase to generate the DID secrets.

4. After you entered the recovery phrase, one of the steps will ask if you would like to use your existing DID, select `yes`.

This process will allow you to retain the same DID and DID secrets, including the DID document.

**Note:** The recovery phrase only restores the DID and its secrets, not the full profile configuration, such as contacts, relationships, and logs.
