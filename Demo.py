import requests
import json
import re

#ASCII banner
print("""
██████╗ ███╗   ██╗███████╗   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗  █████╗    ██╗
██╔══██╗████╗  ██║██╔════╝  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║ ██╔══██╗   ██║
██║  ██║██╔██╗ ██║███████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║ ███████║   ██║
██║  ██║██║╚██╗██║╚════██║  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║ ██╔══██║   ██║
██████╔╝██║ ╚████║███████║  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║ ██║  ██║██╗██║██╗
╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═╝  ╚═╝╚═╝╚═╝╚═╝
                                                                                                    """)
# Choose the model
while True:
    print("Choose the model to use (currently only Meta-Llama-3-8B is supported): ") 
    print("(1) Meta-Llama-3-8B")
    print("To be added...")
    answer= input()
    if (answer=="1"):
        model="Meta-Llama-3-8B-Instruct.Q4_0.gguf"
        break
    else:
        print("not a valid model")

while True:
    # Define the API endpoint
    api_url = 'http://localhost:4891/v1/chat/completions'
        
    # Get user input for the website
    website = input("Enter the website to check (e.g., 'google.com'): ")

    # Define the payload with the dynamic website input
    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": f"Is the website {website} malicious? Please answer with yes or no."}
        ],
        "max_tokens": 50,
        "temperature": 0.28
    }

    # Set the headers
    headers = {
        "Content-Type": "application/json"
    }

    try:
        # Make the POST request
        response = requests.post(api_url, headers=headers, data=json.dumps(payload))
        
        # Check if the request was successful
        response.raise_for_status()
        
        # Parse the response
        result = response.json()
        
        # Isolate the answer
        answer = re.sub(r'[^A-Za-z]', '',result['choices'][0]['message']['content'])
        if (answer=="no"or answer=="No" or answer=="NO"):
            # Print the answer
            print("Safe")
        elif (answer=="yes" or answer=="Yes" or answer=="YES"):
            # Print the answer
            print("Malicious")
        else:
            print("Not Sure")
            ##print("Isolated Answer:", answer)
    except requests.RequestException as e:
        # Print any errors
        print(f"Request Error: {e}")
