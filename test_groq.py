import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")

if not api_key:
    raise RuntimeError("GROQ_API_KEY was not found.")

print("Groq key found.")
print("Key prefix:", api_key[:4])
print("Key length:", len(api_key))

client = Groq(api_key=api_key)

response = client.chat.completions.create(
    model="openai/gpt-oss-20b",
    messages=[
        {
            "role": "user",
            "content": "Say hello to KAVACH CyberAgent in one sentence."
        }
    ]
)

print("\nGroq response:")
print(response.choices[0].message.content)