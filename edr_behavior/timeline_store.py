"""
Real-Time Attack Timeline Event Store

Provides append-only event logging with multi-dimensional indexing for fast
timeline queries (by timestamp, host, user, process, MITRE technique).

Supports both real-time Kafka streams and forensic mode (stored events).
"""

import json
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import bisect


class EventMode(Enum):
    """Timeline event modes"""
    LIVE = "live"  # Real-time from Kafka
    FORENSIC = "forensic"  # Stored in timeline


@dataclass
class TimelineEvent:
    """Standardized event for timeline"""
    timestamp: str  # ISO format
    event_id: str
    tenant_id: str
    host_id: str
    user_id: Optional[str]
    process_id: Optional[str]
    parent_process_id: Optional[str]
    process_name: str
    event_type: str  # "process_create", "network_connection", "file_access", etc.
    severity: str  # "critical", "high", "medium", "low"
    source: str  # "edr_agent", "siem", "endpoint"
    
    # MITRE ATT&CK context
    mitre_techniques: List[str] = field(default_factory=list)  # ["T1234", "T5678"]
    mitre_tactics: List[str] = field(default_factory=list)  # ["execution", "persistence"]
    
    # Event-specific data
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Timeline metadata
    mode: EventMode = EventMode.FORENSIC
    tags: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary, handling enums"""
        data = asdict(self)
        data['mode'] = self.mode.value
        return data


class TimelineIndex:
    """Multi-dimensional index for fast timeline queries"""
    
    def __init__(self):
        """Initialize indices"""
        self.events_by_timestamp: List[Tuple[float, str]] = []  # (timestamp_float, event_id)
        self.events_by_host: Dict[str, deque] = defaultdict(deque)
        self.events_by_user: Dict[str, deque] = defaultdict(deque)
        self.events_by_process: Dict[str, deque] = defaultdict(deque)
        self.events_by_mitre: Dict[str, deque] = defaultdict(deque)
        self.events_by_type: Dict[str, deque] = defaultdict(deque)
        self.lock = threading.RLock()
    
    def add(self, event: TimelineEvent, event_id: str):
        """Add event to all indices"""
        with self.lock:
            # Convert ISO timestamp to float for binary search
            dt = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
            ts_float = dt.timestamp()
            
            # Insert into timestamp index (keeping sorted)
            bisect.insort(self.events_by_timestamp, (ts_float, event_id))
            
            # Add to other indices
            self.events_by_host[event.host_id].append(event_id)
            if event.user_id:
                self.events_by_user[event.user_id].append(event_id)
            if event.process_id:
                self.events_by_process[event.process_id].append(event_id)
            for mitre in event.mitre_techniques:
                self.events_by_mitre[mitre].append(event_id)
            self.events_by_type[event.event_type].append(event_id)
    
    def query_range(self, start_ts: float, end_ts: float) -> List[str]:
        """Get all event IDs in timestamp range"""
        with self.lock:
            start_idx = bisect.bisect_left(self.events_by_timestamp, (start_ts,))
            end_idx = bisect.bisect_right(self.events_by_timestamp, (end_ts, "~"))
            return [eid for _, eid in self.events_by_timestamp[start_idx:end_idx]]
    
    def clear(self):
        """Clear all indices"""
        with self.lock:
            self.events_by_timestamp.clear()
            self.events_by_host.clear()
            self.events_by_user.clear()
            self.events_by_process.clear()
            self.events_by_mitre.clear()
            self.events_by_type.clear()


class TimelineEventStore:
    """
    Append-only timeline event store with multi-dimensional indexing.
    
    Supports:
    - Real-time event ingestion from Kafka
    - Forensic mode queries with time range filtering
    - Tenant isolation
    - High-performance indexing
    """
    
    def __init__(self, max_events_per_tenant: int = 100000):
        """
        Initialize timeline store
        
        Args:
            max_events_per_tenant: Maximum events to keep per tenant (FIFO eviction)
        """
        self.max_events_per_tenant = max_events_per_tenant
        
        # Per-tenant storage
        self.events_by_tenant: Dict[str, Dict[str, TimelineEvent]] = defaultdict(dict)
        self.indices: Dict[str, TimelineIndex] = defaultdict(TimelineIndex)
        
        # Event ordering per tenant
        self.event_queue: Dict[str, deque] = defaultdict(deque)
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'events_per_tenant': defaultdict(int),
            'last_event_timestamp': None,
        }
    
    def add_event(self, event: TimelineEvent) -> str:
        """
        Add event to timeline store
        
        Args:
            event: TimelineEvent to add
            
        Returns:
            Event ID
        """
        with self.lock:
            # Generate event ID if not present
            if not event.event_id:
                event.event_id = f"{event.tenant_id}_{event.timestamp}_{id(event)}"
            
            event_id = event.event_id
            tenant_id = event.tenant_id
            
            # Store event
            self.events_by_tenant[tenant_id][event_id] = event
            self.event_queue[tenant_id].append(event_id)
            
            # Update index
            self.indices[tenant_id].add(event, event_id)
            
            # Update statistics
            self.stats['total_events'] += 1
            self.stats['events_per_tenant'][tenant_id] += 1
            self.stats['last_event_timestamp'] = event.timestamp
            
            # Enforce max events per tenant (FIFO eviction)
            if len(self.event_queue[tenant_id]) > self.max_events_per_tenant:
                evicted_id = self.event_queue[tenant_id].popleft()
                del self.events_by_tenant[tenant_id][evicted_id]
                self.stats['events_per_tenant'][tenant_id] -= 1
            
            return event_id
    
    def get_event(self, tenant_id: str, event_id: str) -> Optional[TimelineEvent]:
        """Get single event by ID"""
        with self.lock:
            return self.events_by_tenant[tenant_id].get(event_id)
    
    def query_range(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[TimelineEvent]:
        """
        Query events in time range with optional filters
        
        Args:
            tenant_id: Tenant ID
            start_time: Start timestamp
            end_time: End timestamp
            filters: Optional filtering dict with keys:
                - host_id: Filter by host
                - user_id: Filter by user
                - process_id: Filter by process
                - event_type: Filter by event type
                - severity: Filter by severity
                - mitre_technique: Filter by MITRE technique
        
        Returns:
            List of TimelineEvent objects
        """
        filters = filters or {}
        
        with self.lock:
            # Get base event IDs from timestamp range
            start_ts = start_time.timestamp()
            end_ts = end_time.timestamp()
            event_ids = self.indices[tenant_id].query_range(start_ts, end_ts)
            
            # Apply additional filters
            result = []
            for event_id in event_ids:
                event = self.events_by_tenant[tenant_id].get(event_id)
                if not event:
                    continue
                
                # Apply filters
                if filters.get('host_id') and event.host_id != filters['host_id']:
                    continue
                if filters.get('user_id') and event.user_id != filters['user_id']:
                    continue
                if filters.get('process_id') and event.process_id != filters['process_id']:
                    continue
                if filters.get('event_type') and event.event_type != filters['event_type']:
                    continue
                if filters.get('severity') and event.severity != filters['severity']:
                    continue
                if filters.get('mitre_technique'):
                    if filters['mitre_technique'] not in event.mitre_techniques:
                        continue
                
                result.append(event)
            
            return result
    
    def query_process_tree(
        self,
        tenant_id: str,
        process_id: str,
        start_time: datetime,
        end_time: datetime,
        include_children: bool = True,
        include_parent: bool = True
    ) -> Dict[str, Any]:
        """
        Get process tree context for forensics
        
        Args:
            tenant_id: Tenant ID
            process_id: Root process ID
            start_time: Time range start
            end_time: Time range end
            include_children: Include child processes
            include_parent: Include parent process
        
        Returns:
            Process tree dict with parent/child relationships
        """
        with self.lock:
            events = self.query_range(tenant_id, start_time, end_time, {
                'process_id': process_id
            })
            
            result = {
                'root_process_id': process_id,
                'root_event': events[0] if events else None,
                'children': {},
                'parent': None,
            }
            
            if not events:
                return result
            
            root_event = events[0]
            
            # Get parent if requested
            if include_parent and root_event.parent_process_id:
                parent_events = self.query_range(tenant_id, start_time, end_time, {
                    'process_id': root_event.parent_process_id
                })
                if parent_events:
                    result['parent'] = parent_events[0]
            
            # Get children if requested
            if include_children:
                all_events = self.query_range(
                    tenant_id, start_time, end_time,
                    {'host_id': root_event.host_id}
                )
                children_by_id = defaultdict(list)
                for event in all_events:
                    if event.parent_process_id == process_id:
                        children_by_id[event.process_id].append(event)
                
                result['children'] = {
                    pid: events[0] for pid, events in children_by_id.items()
                }
            
            return result
    
    def get_stats(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Get timeline statistics"""
        with self.lock:
            if tenant_id:
                return {
                    'tenant_id': tenant_id,
                    'total_events': len(self.events_by_tenant[tenant_id]),
                    'last_event_timestamp': self.stats['last_event_timestamp'],
                    'mode': 'forensic',
                }
            
            return {
                'total_events': self.stats['total_events'],
                'tenants': len(self.events_by_tenant),
                'events_per_tenant': dict(self.stats['events_per_tenant']),
                'last_event_timestamp': self.stats['last_event_timestamp'],
            }
    
    def clear(self, tenant_id: Optional[str] = None):
        """Clear events"""
        with self.lock:
            if tenant_id:
                self.events_by_tenant[tenant_id].clear()
                self.event_queue[tenant_id].clear()
                self.indices[tenant_id] = TimelineIndex()
                self.stats['events_per_tenant'][tenant_id] = 0
            else:
                self.events_by_tenant.clear()
                self.event_queue.clear()
                self.indices.clear()
                self.stats['events_per_tenant'].clear()
    
    def export_jsonl(self, tenant_id: str, filepath: str):
        """Export timeline events to JSONL for archival"""
        with self.lock:
            with open(filepath, 'w') as f:
                for event_id in self.event_queue[tenant_id]:
                    event = self.events_by_tenant[tenant_id].get(event_id)
                    if event:
                        f.write(json.dumps(event.to_dict()) + '\n')
    
    def import_jsonl(self, tenant_id: str, filepath: str):
        """Import timeline events from JSONL"""
        with self.lock:
            with open(filepath, 'r') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        event = TimelineEvent(
                            timestamp=data['timestamp'],
                            event_id=data['event_id'],
                            tenant_id=data['tenant_id'],
                            host_id=data['host_id'],
                            user_id=data.get('user_id'),
                            process_id=data.get('process_id'),
                            parent_process_id=data.get('parent_process_id'),
                            process_name=data['process_name'],
                            event_type=data['event_type'],
                            severity=data['severity'],
                            source=data['source'],
                            mitre_techniques=data.get('mitre_techniques', []),
                            mitre_tactics=data.get('mitre_tactics', []),
                            details=data.get('details', {}),
                            mode=EventMode(data.get('mode', 'forensic')),
                            tags=data.get('tags', []),
                        )
                        self.add_event(event)


# Singleton instance
_timeline_store: Optional[TimelineEventStore] = None


def get_timeline_store() -> TimelineEventStore:
    """Get or create timeline store singleton"""
    global _timeline_store
    if _timeline_store is None:
        _timeline_store = TimelineEventStore()
    return _timeline_store


def init_timeline_store(max_events: int = 100000) -> TimelineEventStore:
    """Initialize timeline store (for testing)"""
    global _timeline_store
    _timeline_store = TimelineEventStore(max_events_per_tenant=max_events)
    return _timeline_store
