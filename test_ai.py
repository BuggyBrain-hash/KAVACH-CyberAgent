import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    print("ERROR: OPENAI_API_KEY was not found.")
    exit()

client = OpenAI(api_key=api_key)

response = client.responses.create(
    model="gpt-5.6",
    input="Say hello to KAVACH CyberAgent in one sentence."
)

print("\nAI Response:")
print(response.output_text)