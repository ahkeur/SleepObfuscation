# SleepObfuscation

The `main.c` file contains a program that demonstrates a technique called "Sleep Obfuscation" using the Windows API. The program encrypts the memory of the running process while it is sleeping to avoid detection by security software. Here is a brief overview of what the code does:

## Steps

1. **Function Declarations and Typedefs**: The code declares function pointers for `NtAlertResumeThread` and `NtSignalAndWaitForSingleObject` from `ntdll.dll`.

2. **Key Generation**: The `generateKey` function generates a 16-byte random key used for encryption.

3. **SecureSleep Function**: The `SecureSleep` function performs the following steps:
    - Retrieves the addresses of necessary functions from `ntdll.dll` and `advapi32.dll`.
    - Generates a random encryption key and prepares the memory regions for encryption.
    - Creates a suspended thread and sets up multiple contexts (`ctxA`, `ctxB`, `ctxC`, `ctxD`, `ctxE`, `ctxEvent`, `ctxEnd`) to perform different actions such as changing memory protection, encrypting memory, sleeping, and restoring memory protection.
    - Uses `QueueUserAPC` to queue these actions to the thread.
    - Resumes the thread and waits for the event to be signaled.

4. **Main Function**: The `main` function prints some information, waits for user input, and then calls `SecureSleep` to sleep for 10 seconds while encrypting the process memory.

This technique is used to hide the process's memory contents during sleep, making it harder for security software to analyze the process.

5. **Call Stack Spoofing**: Instead of using the default `Sleep` function, the program calls `MessageBox` to spoof the call stack. This makes it appear as though the program is displaying a message box, further obfuscating its true behavior.

(thanks chatgpt for this cute description)

## TODO : 
- Ensure encryption works
- Use undocumented functions to perform actions
- Jump back to main thread when the secure sleep has been done

## Credits

https://github.com/Cracked5pider/Ekko
https://github.com/hotelzululima/KrakenMask
