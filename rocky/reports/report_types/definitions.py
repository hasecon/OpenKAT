from abc import ABC
from datetime import datetime
from logging import getLogger
from pathlib import Path
from typing import Any, Dict, List, Set, TypedDict

from octopoes.connector.octopoes import OctopoesAPIConnector
from octopoes.models.types import OOIType

REPORTS_DIR = Path(__file__).parent
logger = getLogger(__name__)


class ReportPlugins(TypedDict):
    required: List[str]
    optional: List[str]


class AggregateReportSubReports(TypedDict):
    required: List[str]
    optional: List[str]


class Report(ABC):
    id: str
    name: str
    description: str
    plugins: ReportPlugins
    input_ooi_types: Set[OOIType]
    template_path: str = "report.html"

    def __init__(self, octopoes_api_connector: OctopoesAPIConnector):
        self.octopoes_api_connector = octopoes_api_connector

    def generate_data(self, input_ooi: str, valid_time: datetime) -> Dict[str, Any]:
        raise NotImplementedError

    @classmethod
    def class_attributes(cls) -> Dict[str, any]:
        return {
            "id": cls.id,
            "name": cls.name,
            "description": cls.description,
            "plugins": cls.plugins,
            "input_ooi_types": cls.input_ooi_types,
            "template_path": cls.template_path,
        }


class AggregateReport(ABC):
    id: str
    name: str
    description: str
    reports: AggregateReportSubReports
    template_path: str = "report.html"

    def __init__(self, octopoes_api_connector):
        self.octopoes_api_connector = octopoes_api_connector

    def post_process_data(self, data: Dict[str, Any], valid_time: datetime) -> Dict[str, Any]:
        raise NotImplementedError


class MultiReport(ABC):
    id: str
    name: str
    description: str
    plugins: ReportPlugins
    input_ooi_types: Set[OOIType]
    template_path: str = "report.html"

    def __init__(self, octopoes_api_connector):
        self.octopoes_api_connector = octopoes_api_connector

    def post_process_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class ReportType(TypedDict):
    id: str
    name: str
    description: str
