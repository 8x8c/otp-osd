# One Time Pad- One Step Down

Goal- to make a One Time Pad inspired encryption app that is only one step down from the absolute security that a properly implemented OTP has. Why? Because the OTP method is not easy to pull off in real life, a single veer from the strict requirements ruins the absolute security. So this custom encryption  app aims to make otp usage LESS hard on the user, to  just go one step down from the strict OTP method. Being one step down, it is not perfect security, but its pretty dam close. 


Its like a one time pad but the full length key is made in memory and xored byte by byte. 

Under the hood, ChaCha20 generates a keystream byte by byte for the entire length of the file. Then each file byte is XORed with the corresponding keystream byte. So it’s doing the same “per-byte XOR” as a true OTP.

The difference:

A true OTP requires a full-length, truly random key that’s used once and then discarded. This yields information-theoretic security.
In this “one step down” approach, the keystream is deterministically expanded from a short (32-byte) master key plus a nonce using ChaCha20. It provides computational security (as long as ChaCha20 remains secure), and is vastly more practical for large files.
Functionally, though, you do get that same “XOR each plaintext byte with a unique keystream byte” behavior.

With this app tho, you do not have to change the 32 byte key file (key.key) becasuse every time you encrypt, it uses the 32 byte key.key to make a larger key in memory. EVERY time you encrypt, a different key is made, and the nonce is injected into the cyphertext so the app knows how to decrypt it. 

# Is This Approach Truly "One Step Down" from OTP?

Short answer: Yes. Using a stream cipher (like ChaCha20) to XOR files with a per-file keystream generated from a shorter, persistent master key and a new nonce each time is a well-known and widely used practice. It is commonly seen as the "best practical alternative" (or “one step down”) from a true one-time pad. 
