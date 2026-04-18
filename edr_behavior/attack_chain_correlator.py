"""
Attack Chain Event Correlator

Correlates security events into attack chains using:
- Process lineage reconstruction
- MITRE ATT&CK technique mapping
- Anomaly scoring
- Kill-chain progression detection
"""

import threading
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

from .timeline_store import TimelineEvent, TimelineEventStore, get_timeline_store


class KillChainPhase(Enum):
    """MITRE Kill Chain phases"""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_and_control"
    ACTIONS = "actions_on_objectives"


@dataclass
class AttackChainNode:
    """Single node in attack chain"""
    event_id: str
    event: TimelineEvent
    process_id: Optional[str]
    process_name: str
    timestamp: str
    severity: str
    kill_chain_phase: Optional[KillChainPhase] = None
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    anomaly_score: float = 0.0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        data = asdict(self)
        if self.kill_chain_phase:
            data['kill_chain_phase'] = self.kill_chain_phase.value
        return data


@dataclass
class AttackChain:
    """
    Complete attack chain representing a sequence of correlated events
    that form a cohesive attack narrative
    """
    chain_id: str
    tenant_id: str
    root_process_id: Optional[str]
    root_event_id: str
    events: List[AttackChainNode] = field(default_factory=list)
    process_tree: Dict[str, Any] = field(default_factory=dict)
    timeline: List[str] = field(default_factory=list)  # Event IDs in order
    kill_chain_progression: List[Tuple[str, float]] = field(default_factory=list)  # (phase, timestamp)
    total_anomaly_score: float = 0.0
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)
    start_timestamp: Optional[str] = None
    end_timestamp: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'chain_id': self.chain_id,
            'tenant_id': self.tenant_id,
            'root_process_id': self.root_process_id,
            'root_event_id': self.root_event_id,
            'events': [e.to_dict() for e in self.events],
            'timeline': self.timeline,
            'total_anomaly_score': self.total_anomaly_score,
            'severity': self.severity,
            'tags': self.tags,
            'start_timestamp': self.start_timestamp,
            'end_timestamp': self.end_timestamp,
            'num_events': len(self.events),
        }


class AttackChainCorrelator:
    """
    Correlates timeline events into attack chains using process lineage
    and MITRE ATT&CK mapping
    """
    
    def __init__(self, timeline_store: Optional[TimelineEventStore] = None):
        """Initialize correlator"""
        self.store = timeline_store or get_timeline_store()
        self.chains: Dict[str, AttackChain] = {}
        self.lock = threading.RLock()
        
        # MITRE technique to kill chain mapping
        self.mitre_to_killchain = self._build_mitre_mapping()
    
    def _build_mitre_mapping(self) -> Dict[str, KillChainPhase]:
        """Map MITRE techniques to kill chain phases"""
        return {
            # Reconnaissance
            'T1589': KillChainPhase.RECONNAISSANCE,  # Gather Victim Identity Information
            'T1592': KillChainPhase.RECONNAISSANCE,  # Gather Victim Host Information
            
            # Weaponization
            'T1583': KillChainPhase.WEAPONIZATION,  # Acquire Infrastructure
            'T1586': KillChainPhase.WEAPONIZATION,  # Compromise Accounts
            
            # Delivery
            'T1598': KillChainPhase.DELIVERY,  # Phishing
            'T1091': KillChainPhase.DELIVERY,  # Replication Through Removable Media
            'T1195': KillChainPhase.DELIVERY,  # Supply Chain Compromise
            
            # Exploitation
            'T1200': KillChainPhase.EXPLOITATION,  # Hardware Additions
            'T1203': KillChainPhase.EXPLOITATION,  # Exploitation for Client Execution
            'T1190': KillChainPhase.EXPLOITATION,  # Exploit Public-Facing Application
            'T1068': KillChainPhase.EXPLOITATION,  # Abuse Elevation Control Mechanism
            
            # Installation
            'T1547': KillChainPhase.INSTALLATION,  # Boot or Logon Autostart Execution
            'T1137': KillChainPhase.INSTALLATION,  # Office Template Injections
            'T1554': KillChainPhase.INSTALLATION,  # Compromise Client Software Binary
            'T1554': KillChainPhase.INSTALLATION,  # Rootkit
            
            # Command & Control
            'T1071': KillChainPhase.COMMAND_CONTROL,  # Application Layer Protocol
            'T1092': KillChainPhase.COMMAND_CONTROL,  # Communication Through Removable Media
            'T1001': KillChainPhase.COMMAND_CONTROL,  # Data Obfuscation
            'T1008': KillChainPhase.COMMAND_CONTROL,  # Fallback Channels
            
            # Actions on Objectives
            'T1531': KillChainPhase.ACTIONS,  # Account Access Removal
            'T1531': KillChainPhase.ACTIONS,  # Data Destruction
            'T1561': KillChainPhase.ACTIONS,  # Disk Wipe
            'T1499': KillChainPhase.ACTIONS,  # Service Exhaustion Flood
        }
    
    def correlate_events(
        self,
        tenant_id: str,
        events: List[TimelineEvent],
        chain_id: Optional[str] = None
    ) -> AttackChain:
        """
        Correlate events into a single attack chain
        
        Args:
            tenant_id: Tenant ID
            events: List of TimelineEvent objects
            chain_id: Optional chain ID (auto-generated if not provided)
        
        Returns:
            AttackChain object
        """
        if not events:
            raise ValueError("No events provided for correlation")
        
        with self.lock:
            # Generate chain ID if needed
            if not chain_id:
                chain_id = f"{tenant_id}_chain_{events[0].event_id}"
            
            # Sort events by timestamp
            events = sorted(events, key=lambda e: e.timestamp)
            
            # Build attack chain
            chain = AttackChain(
                chain_id=chain_id,
                tenant_id=tenant_id,
                root_process_id=events[0].process_id,
                root_event_id=events[0].event_id,
                start_timestamp=events[0].timestamp,
                end_timestamp=events[-1].timestamp,
            )
            
            # Build process tree
            chain.process_tree = self._build_process_tree(events)
            
            # Add events as chain nodes
            total_anomaly = 0.0
            for event in events:
                # Determine kill chain phase
                phase = None
                for technique in event.mitre_techniques:
                    if technique in self.mitre_to_killchain:
                        phase = self.mitre_to_killchain[technique]
                        break
                
                # Estimate anomaly score based on severity and techniques
                anomaly_score = self._calculate_anomaly_score(event)
                total_anomaly += anomaly_score
                
                # Create chain node
                node = AttackChainNode(
                    event_id=event.event_id,
                    event=event,
                    process_id=event.process_id,
                    process_name=event.process_name,
                    timestamp=event.timestamp,
                    severity=event.severity,
                    kill_chain_phase=phase,
                    mitre_techniques=event.mitre_techniques,
                    mitre_tactics=event.mitre_tactics,
                    anomaly_score=anomaly_score,
                )
                
                chain.events.append(node)
                chain.timeline.append(event.event_id)
            
            # Determine overall severity
            severities = [e.severity for e in events]
            if 'critical' in severities:
                chain.severity = 'critical'
            elif 'high' in severities:
                chain.severity = 'high'
            elif 'medium' in severities:
                chain.severity = 'medium'
            else:
                chain.severity = 'low'
            
            # Set total anomaly score
            chain.total_anomaly_score = min(100.0, total_anomaly)
            
            # Detect kill chain progression
            chain.kill_chain_progression = self._detect_kill_chain_progression(chain)
            
            # Auto-tag based on signatures
            chain.tags = self._generate_tags(chain)
            
            # Store chain
            self.chains[chain_id] = chain
            
            return chain
    
    def correlate_by_process_tree(
        self,
        tenant_id: str,
        root_process_id: str,
        start_time: datetime,
        end_time: datetime,
        chain_id: Optional[str] = None
    ) -> AttackChain:
        """
        Correlate events using process tree (parent/child relationships)
        
        Args:
            tenant_id: Tenant ID
            root_process_id: Root process to start chain from
            start_time: Time range start
            end_time: Time range end
            chain_id: Optional chain ID
        
        Returns:
            AttackChain object
        """
        # Get all events for the process
        events = self.store.query_range(
            tenant_id, start_time, end_time,
            {'process_id': root_process_id}
        )
        
        # Also get related process events (children)
        all_events = self.store.query_range(tenant_id, start_time, end_time)
        
        # Filter to only events related to root process tree
        process_tree = self.store.query_process_tree(
            tenant_id, root_process_id, start_time, end_time,
            include_children=True, include_parent=True
        )
        
        process_ids = {root_process_id}
        if process_tree.get('parent'):
            process_ids.add(process_tree['parent'].process_id)
        process_ids.update(process_tree.get('children', {}).keys())
        
        # Filter events to process tree
        related_events = [
            e for e in all_events if e.process_id in process_ids
        ]
        
        return self.correlate_events(tenant_id, related_events, chain_id)
    
    def _build_process_tree(self, events: List[TimelineEvent]) -> Dict[str, Any]:
        """Build parent-child process relationships"""
        tree = defaultdict(lambda: {
            'process_name': '',
            'children': []
        })
        
        for event in events:
            if event.process_id:
                if not tree[event.process_id]['process_name']:
                    tree[event.process_id]['process_name'] = event.process_name
                
                if event.parent_process_id:
                    if event.process_id not in tree[event.parent_process_id]['children']:
                        tree[event.parent_process_id]['children'].append(event.process_id)
        
        return dict(tree)
    
    def _calculate_anomaly_score(self, event: TimelineEvent) -> float:
        """Calculate anomaly score for an event"""
        score = 0.0
        
        # Base score from severity
        severity_scores = {
            'critical': 25.0,
            'high': 15.0,
            'medium': 8.0,
            'low': 2.0,
        }
        score += severity_scores.get(event.severity, 0.0)
        
        # Bonus for MITRE techniques
        score += len(event.mitre_techniques) * 5.0
        
        # Bonus for suspicious event types
        suspicious_types = {
            'privilege_escalation': 15.0,
            'persistence': 10.0,
            'lateral_movement': 12.0,
            'data_exfiltration': 20.0,
            'command_execution': 8.0,
        }
        score += suspicious_types.get(event.event_type, 0.0)
        
        return min(100.0, score)
    
    def _detect_kill_chain_progression(
        self, chain: AttackChain
    ) -> List[Tuple[str, float]]:
        """Detect kill chain phases and progression"""
        phases_seen: Set[str] = set()
        progression = []
        
        for node in chain.events:
            if node.kill_chain_phase:
                phase_str = node.kill_chain_phase.value
                if phase_str not in phases_seen:
                    phases_seen.add(phase_str)
                    # Parse timestamp
                    try:
                        ts = datetime.fromisoformat(node.timestamp.replace('Z', '+00:00')).timestamp()
                        progression.append((phase_str, ts))
                    except:
                        pass
        
        return progression
    
    def _generate_tags(self, chain: AttackChain) -> List[str]:
        """Generate tags based on attack characteristics"""
        tags = []
        
        # Tag by severity
        if chain.severity == 'critical':
            tags.append('critical_threat')
        elif chain.severity == 'high':
            tags.append('high_risk')
        
        # Tag by anomaly score
        if chain.total_anomaly_score > 70:
            tags.append('high_anomaly')
        elif chain.total_anomaly_score > 50:
            tags.append('medium_anomaly')
        
        # Tag by kill chain coverage
        if len(chain.kill_chain_progression) >= 4:
            tags.append('multi_stage_attack')
        
        # Tag by process tree depth
        if chain.process_tree and len(chain.process_tree) > 3:
            tags.append('process_tree_attack')
        
        # Tag by MITRE tactics
        tactics_seen = set()
        for event in chain.events:
            tactics_seen.update(event.mitre_tactics)
        
        if 'persistence' in tactics_seen:
            tags.append('persistence_attempt')
        if 'lateral-movement' in tactics_seen or 'lateral_movement' in tactics_seen:
            tags.append('lateral_movement_detected')
        if 'exfiltration' in tactics_seen:
            tags.append('data_exfiltration_risk')
        
        return tags
    
    def get_chain(self, chain_id: str) -> Optional[AttackChain]:
        """Get attack chain by ID"""
        with self.lock:
            return self.chains.get(chain_id)
    
    def get_chains(self, tenant_id: Optional[str] = None) -> List[AttackChain]:
        """Get all attack chains (optionally filtered by tenant)"""
        with self.lock:
            chains = list(self.chains.values())
            if tenant_id:
                chains = [c for c in chains if c.tenant_id == tenant_id]
            return chains
    
    def get_chains_by_severity(self, tenant_id: str, severity: str) -> List[AttackChain]:
        """Get attack chains by severity level"""
        with self.lock:
            return [
                c for c in self.chains.values()
                if c.tenant_id == tenant_id and c.severity == severity
            ]
    
    def clear(self, tenant_id: Optional[str] = None):
        """Clear chains"""
        with self.lock:
            if tenant_id:
                self.chains = {
                    cid: c for cid, c in self.chains.items()
                    if c.tenant_id != tenant_id
                }
            else:
                self.chains.clear()


# Singleton instance
_correlator: Optional[AttackChainCorrelator] = None


def get_correlator(timeline_store: Optional[TimelineEventStore] = None) -> AttackChainCorrelator:
    """Get or create correlator singleton"""
    global _correlator
    if _correlator is None:
        _correlator = AttackChainCorrelator(timeline_store)
    return _correlator


def init_correlator(timeline_store: Optional[TimelineEventStore] = None) -> AttackChainCorrelator:
    """Initialize correlator (for testing)"""
    global _correlator
    _correlator = AttackChainCorrelator(timeline_store)
    return _correlator
