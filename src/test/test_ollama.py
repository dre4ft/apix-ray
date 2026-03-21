


import asyncio
from ollama_client import OllamaAPIClient

async def chat():
    client = OllamaAPIClient(model_name="qwen2.5-coder:latest")
    resp = await client.chat_completion(messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Quelle est la capitale de la France ?"}
    ])
    #await client.close()
    print(resp)
    

if __name__ == "__main__":
    asyncio.run(chat())