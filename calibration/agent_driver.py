import abc
from typing import Tuple, List, Dict, Optional

class AgentDriver(abc.ABC):
    """
    Abstract interface for a solving-agent driver.
    
    This interface defines how the calibration harness interacts with an agent
    (either a scripted baseline or a real LLM-backed agent).
    """
    
    @abc.abstractmethod
    def run_solve(self, host: str, port: int, turn_budget: int, instruction_text: str) -> Tuple[List[Dict], int, Optional[str]]:
        """
        Runs the agent against the specified target until it solves the challenge,
        exceeds the turn budget, or gives up.
        
        Args:
            host: Target host.
            port: Target port.
            turn_budget: Maximum number of turns (commands/tool calls + observation) allowed.
            instruction_text: Instructions provided to the agent (e.g., from instruction.md).

        Returns:
            A tuple of:
            - transcript: A list of dicts representing the turns taken by the agent. 
                          Format: [{"turn": 1, "action": "...", "observation": "..."}, ...]
            - turns_used: Integer number of turns consumed.
            - final_flag_submitted_or_none: The final flag string output by the agent, or None.
        """
        pass
