import sys
from yachalk import chalk
import pprint
sys.path.append("..")
from openai import OpenAI
import json
# import ollama.vllmclient as client
import httpx
from colorama import Fore, Style


from openai import OpenAI
# Set OpenAI's API key and API base to use vLLM's API server.
openai_api_key = "EMPTY"
openai_api_base = "http://localhost:8000/v1"



##TODO Customize to be domain specific
def extractConcepts(prompt: str, metadata={}, model="yichat:34"):
    """
    Extract key concepts from a given text using a specific AI model.

    This function sends the text to an AI model and processes the response to extract key concepts related to cybersecurity.

    Args:
    prompt (str): The text from which to extract concepts.
    metadata (dict, optional): Additional metadata to append to each concept.
    model (str, optional): The AI model to use for extraction.

    Returns:
    list: A list of extracted concepts, each in the form of a dictionary.
    """

    client = OpenAI(
    api_key=openai_api_key,
    base_url=openai_api_base,
)


    SYS_PROMPT = (
    "Your task is to extract key concepts and non-personal entities related to cybersecurity from the given technical analysis of malware files and families. "
    "Focus on the most crucial and discrete concepts, breaking down complex concepts into simpler, more fundamental elements when necessary. "
    "Classify the concepts into one of the following categories specific to malware analysis: "
    "[indicator of compromise (IOC), file hash, threat actor, malware family, vulnerability, tool, technique, network signature, domain, IP address, URL, artifact, campaign, tactic, procedure, infrastructure, software, organization, document, event, misc]\n"
    "Structure your output as a list in JSON format, using the following template:\n"
    "[\n"
    " {\n"
    ' "entity": The specific cybersecurity concept or entity,\n'
    ' "importance": The contextual importance of the entity in the scope of malware analysis on a scale of 1 to 5 (5 being the highest),\n'
    ' "category": The category of the entity as listed above,\n'
    " },\n"
    "{ },\n"
    "]\n"
    "Ensure the extracted information is accurate and relevant to the cybersecurity context, highlighting the connections between malware attributes and their implications for security postures.\r\n"
    "IMPORTANT your respons should contain only JSON.  Make sure it is valid JSON.  Remember to escape backslashes and quotes as required.\r\n"
    "DO NOT provide additional text or Explanation"
    )

    chat_response = client.chat.completions.create(
    model="HuggingFaceH4/zephyr-7b-beta",
    messages=[
        {"role": "system", "content": f"{SYS_PROMPT}"},
        {"role": "user", "content": f"{prompt}"},
    ]
)
    print("Chat response:", chat_response)
    # # response, _ = client.generate(model_name=model, system=SYS_PROMPT, prompt=prompt)
    # try:
    #     result = json.loads(response)
    #     result = [dict(item, **metadata) for item in result]
    #     pprint.pprint(result)
    # except:
    #     print("\n\nERROR ### Here is the buggy response: ", response, "\n\n")
    #     result = None
    # return result

def graphPrompt(text, chunk_id=None, model="HuggingFaceH4/zephyr-7b-beta"):
    """
    Analyze a text to extract relationships between entities and represent them as a graph.

    This function uses an AI model to parse a given text and identify relationships between various cybersecurity-related entities.

    Args:
        text (str): The text to analyze.
        chunk_id (str, optional): The chunk ID associated with the text.
        model (str, optional): The AI model to use for analysis.

    Returns:
        list: A list of graph nodes and edges, each in the form of a dictionary.
    """

    SYS_PROMPT = (
        "As an entity relationship analyzer specializing in cybersecurity, your objective is to parse technical documents on malware analysis and distill key information into a structured network graph. "
        "You will receive excerpts of text (enclosed within triple backticks) containing technical descriptions and analyses of malware threats. Your task is to extract the essential ontology of terms related to malware attributes, indicators of compromise (IOCs), threat actors, and cybersecurity measures mentioned within the text. \n"
        "Thought 1: As you evaluate each sentence, identify the fundamental terms. These may encompass cybersecurity-specific objects, entities, malware families, techniques, vulnerabilities, infrastructures, and other relevant terms. Focus on atomistic and granular details.\n\n"
        "Thought 2: Define the relationship for each identified pair of related terms based on their context within the cybersecurity domain. \n\n"
        "Your analysis should be precise, capturing the complex interplay of terms within the context of malware and cybersecurity.\r\n"
        "Only capture the following nodes: file, url, malware, vulnerability, threat actor, tool, technique, network signature, domain, ip address, artifact, campaign, tactic, procedure, infrastructure, software, organization, document, event/\r\n"
        "*** IMPORTANT your response should contain only JSON.  Make sure it is valid JSON.  Remember to escape backslashes and quotes as required.\r\n"
        "INSTRUCTION: Present your findings in a JSON list format. Each entry should detail only contain a pair of related terms (node_1 and node_2) along with a description of their relationship. \r\n\ Do not include Explanation:/Notes: The output should be constructed as follows: \n"
        "```json"
        ' [{"node_1": "Malware entity", "node_2": "503360fcb8c42a8e1256fa2e5744f1291e50312e14d63998c33963b40f72b059","edge": "has_sha"},\n"'
        ' {"node_1": "503360fcb8c42a8e1256fa2e5744f1291e50312e14d63998c33963b40f72b059", "node_2": "Darkbit","edge": "detected_as"},\n"'
        ' {"node_1": "503360fcb8c42a8e1256fa2e5744f1291e50312e14d63998c33963b40f72b059", "node_2": "Ransomware","edge": "type_of"},\n"'
        ' {"node_1": "Malware entity", "node_2": "f8022b973900c783fd861ede7d0ac02f665c041b9cd0641be7318999fb82ce8f","edge": "has_sha"},\n"'
        ' {"node_1": "503360fcb8c42a8e1256fa2e5744f1291e50312e14d63998c33963b40f72b059", "node_2": "Kwampirs Dropper","edge": "detected_as"},\n"'
        ' {"node_1": "File path C:\\\\Windows\\\\System32\\\\hhelper.exe", "node_2": "2c50eedc260c82dc176447aa4116ad37112864f4e1e3e95c4817499d9f18a90d)","edge": "has_sha"},\n"'
        ' {"node_1": "503360fcb8c42a8e1256fa2e5744f1291e50312e14d63998c33963b40f72b059", "node_2": "Dropper","edge": "type_of"}]"'
        "```"
        #"]\n"

    )

    user_prompt = f"context: ```{text}``` \n\n output: "

    openai_api_key = "EMPTY"
    openai_api_base = "http://localhost:8000/v1"

    client = OpenAI(api_key=openai_api_key, base_url=openai_api_base)

    chat_response = client.chat.completions.create(
        model="HuggingFaceH4/zephyr-7b-beta",
        temperature=0.5,
        presence_penalty=1.2,
        messages=[
            {"role": "system", "content": f"{SYS_PROMPT}"},
            {"role": "user", "content": f"{user_prompt}"},
        ]
    )

    try:
        # Extracting the content from the chat response
        response_content = chat_response.choices[0].message.content


        #First we're going to look for embedded json
        first_backtick_pos = response_content.find("```json")
        if first_backtick_pos != -1:
            print(Fore.CYAN + "Found embedded json")
            # Find the second occurrence starting from the character after the first occurrence
            second_backtick_pos = response_content.find("```", first_backtick_pos + 3)
            if second_backtick_pos != -1:
                print(Fore.CYAN +"Found second backtick")
                # Cut the text at the position of the second triple backticks
                #return text[first_backtick_pos:second_backtick_pos]
                response_content = response_content[first_backtick_pos:second_backtick_pos]

           # Check and fix malformed content
        if response_content.startswith('```json'):
            response_content = response_content[7:]
        if response_content.endswith('```'):
            response_content = response_content[:-3]
        #sometimes there is an extra trailing , so lets remove it
        if response_content.endswith(','):
            response_content = response_content[:-1]
        #sometimes it ends and starts with {} so lets add [] back so that it is proper
        if response_content.startswith('{') and response_content.endswith('}'):
            print(Fore.CYAN + "Found start and wend with {}")
            response_content = '[' + response_content + ']'
        



        # Parsing the JSON from the response content
        result = json.loads(response_content)
        print(Fore.GREEN + "Result:")
        pprint.pprint(result)
        print(Style.RESET_ALL)


        if chunk_id is not None:
            # Add chunk_id to each item in the result
            result = [dict(item, chunk_id=chunk_id) for item in result]

    except Exception as e:
        print(e)
        print(Fore.RED + "\n\nERROR ### Here is the buggy response: ", response_content, "\n\n")
        print(Style.RESET_ALL) 
        result = None
        # Logging the error
        error_log_content = f"input:\r\n{text}\r\nresponse:\r\n{response_content}\r\n------------------\n\n"
        with open("error.log", "a") as f:
            f.write(error_log_content)

    return result

async def async_graphPrompt(text, chunk_id=None, model="HuggingFaceH4/zephyr-7b-beta"):
    """
    Analyze a text to extract relationships between entities and represent them as a graph.

    This function uses an AI model to parse a given text and identify relationships between various cybersecurity-related entities.

    Args:
        text (str): The text to analyze.
        chunk_id (str, optional): The chunk ID associated with the text.
        model (str, optional): The AI model to use for analysis.

    Returns:
        list: A list of graph nodes and edges, each in the form of a dictionary.
    """
    SYS_PROMPT = (
        "As an entity relationship analyzer specializing in cybersecurity, your objective is to parse technical documents on malware analysis and distill key information into a structured network graph. "
        "You will receive excerpts of text (enclosed within triple backticks) containing technical descriptions and analyses of malware threats. Your task is to extract the essential ontology of terms related to malware attributes, indicators of compromise (IOCs), threat actors, and cybersecurity measures mentioned within the text. \n"
        "Thought 1: As you evaluate each sentence, identify the fundamental terms. These may encompass cybersecurity-specific objects, entities, malware families, techniques, vulnerabilities, infrastructures, and other relevant terms. Focus on atomistic and granular details.\n\n"
        "Thought 2: Define the relationship for each identified pair of related terms based on their context within the cybersecurity domain. \n\n"
        "INSTRUCTION: Present your findings in a JSON list format. Each entry should detail only contain a pair of related terms (node_1 and node_2) along with a description of their relationship. The output should be constructed as follows: \n"
        "[\n"
        " {\n"
        ' "node_1": "Malware entity",\n'
        ' "node_2": "a related Malware",\n'
        ' "edge": "entity_relationship"\n'
        " }, {...}\n"
        "]\n"
        "Your analysis should be precise, capturing the complex interplay of terms within the context of malware and cybersecurity.\r\n"
        "Only capture the following nodes: file, url, malware, vulnerability, threat actor, tool, technique, network signature, domain, ip address, artifact, campaign, tactic, procedure, infrastructure, software, organization, document, event/\r\n"
    )
    user_prompt = f"context:\r\n{text}\n\n output: "
    openai_api_key = "EMPTY"
    openai_api_base = "http://localhost:8000/v1"

    response_content = None  # Declare variable outside the try block

    async with httpx.AsyncClient() as client:
        chat_response = await client.post(
            json={
                "model": "HuggingFaceH4/zephyr-7b-beta",
                "messages": [
                    {"role": "system", "content": f"{SYS_PROMPT}"},
                    {"role": "user", "content": f"{user_prompt}"},
                ],
            },
            headers={"Authorization": f"Bearer {openai_api_key}"}
        )

    try:
        response_json = chat_response.json()
        if 'choices' in response_json:
            response_content = response_json['choices'][0]['message']['content']
            result = json.loads(response_content)

            if chunk_id is not None:
                result = [dict(item, chunk_id=chunk_id) for item in result]

            return result
        else:
            raise ValueError("Invalid response format")

    except Exception as e:
        print(e)
        error_log_content = f"input:\r\n{text}\r\nresponse:\r\n{response_content if response_content else 'No content'}\r\n------------------\n\n"
        with open("error.log", "a") as f:
            f.write(error_log_content)
        return None