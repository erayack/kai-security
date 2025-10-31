# exploit-agent

## Enviroment

Do not forget to add openrouter api key before start!

```
OPENROUTER_API_KEY="sk-or-v1-asdfasdfsafasdf"
```

## Installation 

```
make install        
```

## Running the scaffold

Go to run_scaffold.py and change `repo_url` in the main function to the URL of the repository you want to search for exploits in.
You can also change num_turns to change the inference budget given to each agent or model_name to change the model used. Then simply, run:
```
make run
```