Post initial scripts for hardening

1. php.sh   - Fix those php configs
2. rbash.sh - Jail 4 u
    ```
    Example: -E 'REVERT=blabla'

    @ PARAMS
    REVERT -    If defined, restores the backed up /etc/password. Optional.
                This is in case rbashing things screwed stuff up.
    ```
3. ssh.sh   - fuck public keys bro