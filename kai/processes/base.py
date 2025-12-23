from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Optional, TYPE_CHECKING
import logging

from kai.schemas import MasterContext

if TYPE_CHECKING:
    from kai.state_manager import KaiStateManager

InputT = TypeVar("InputT")
OutputT = TypeVar("OutputT")

logger = logging.getLogger(__name__)


class BaseProcess(ABC, Generic[InputT, OutputT]):
    """
    Abstract base class for all Kai processes.

    A Process is a discrete unit of work that takes an input,
    performs some logic using the global context, and returns an output.
    """

    def __init__(
        self,
        context: MasterContext,
        state_manager: Optional["KaiStateManager"] = None,
    ):
        self.context = context
        self.state_manager = state_manager
        self.logger = logger.getChild(self.__class__.__name__)

    @abstractmethod
    async def execute(self, input_data: InputT) -> OutputT:
        """
        Core logic of the process. Must be implemented by subclasses.

        Args:
            input_data: The structured input for this process.

        Returns:
            The structured output of this process.
        """
        pass

    async def _save_conversation(
        self,
        agent_id: str,
        agent_type: str,
        messages: list,
        metadata: dict,
    ) -> Optional[str]:
        """
        Save conversation via state manager if available.

        Returns path/URI if saved, None otherwise.
        """
        if not self.state_manager:
            return None
        try:
            return await self.state_manager.save_conversation(
                agent_id=agent_id,
                agent_type=agent_type,
                messages=messages,
                metadata=metadata,
            )
        except Exception as e:
            self.logger.warning(f"Failed to save conversation: {e}")
            return None

    async def run(self, input_data: InputT) -> OutputT:
        """
        Executes the process with logging and error handling wrapper.

        Args:
            input_data: The structured input for this process.

        Returns:
            The structured output of this process.

        Raises:
            Exception: If the process execution fails.
        """
        self.logger.info(
            f"Starting process execution with input type: {type(input_data).__name__}"
        )
        try:
            result = await self.execute(input_data)
            self.logger.info("Process execution completed successfully")
            return result
        except Exception as e:
            self.logger.error(f"Process execution failed: {str(e)}", exc_info=True)
            raise e
