from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langgraph.graph import END, MessagesState, StateGraph

from nodes import run_agent_reasoning, tool_node

load_dotenv()

AGENT_REASONING = "agent_reason"
ACT = "act"
LAST_MESSAGE = -1
MAX_ITERATIONS = 50

USER_PROMPT = """Find 5 ClickFix-hosting assets via Fofa, extract the malicious PowerShell payloads, and write a markdown report named 'clickfix-2026-04-28.md'.

The report MUST contain these sections:
1. Résumé exécutif (date, dork used, asset count)
2. IOCs (defanged) — markdown table
3. Payloads PowerShell extraits — one ```powershell``` block per sample
4. TTPs observées
5. Méthodologie"""


def should_continue(state: MessagesState) -> str:
    if not state["messages"][LAST_MESSAGE].tool_calls:
        return END
    return ACT


flow = StateGraph(MessagesState)
flow.add_node(AGENT_REASONING, run_agent_reasoning)
flow.add_node(ACT, tool_node)
flow.set_entry_point(AGENT_REASONING)
flow.add_conditional_edges(AGENT_REASONING, should_continue, {END: END, ACT: ACT})
flow.add_edge(ACT, AGENT_REASONING)

app = flow.compile()
app.get_graph().draw_mermaid_png(output_file_path="flow.png")


def main() -> None:
    res = app.invoke(
        {"messages": [HumanMessage(content=USER_PROMPT)]},
        config={"recursion_limit": MAX_ITERATIONS},
    )
    print(res["messages"][LAST_MESSAGE].content)


if __name__ == "__main__":
    main()
