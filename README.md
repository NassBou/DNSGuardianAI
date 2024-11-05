# DNSGuardianAI

```plaintext
██████╗ ███╗   ██╗███████╗   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗  █████╗    ██╗
██╔══██╗████╗  ██║██╔════╝  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║ ██╔══██╗   ██║
██║  ██║██╔██╗ ██║███████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║ ███████║   ██║
██║  ██║██║╚██╗██║╚════██║  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║ ██╔══██║   ██║
██████╔╝██║ ╚████║███████║  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║ ██║  ██║██╗██║██╗
```
DNSGuardianAI is an AI-powered tool designed to detect potentially harmful DNS queries.

# How to run
This demo uses GPT4All and the Meta Llama-3 8B model so GPT4All should be running with the Local API Server enabled and running at port 4891. 

Different/custom models can be loaded by removing the call for getmodel() and adding the model name in the line: 
model="YOUR_CUSTOM_MODEL".
