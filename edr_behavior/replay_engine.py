"""
Attack Timeline Replay Engine

Provides video-like playback controls for security events:
- Play/pause/step forward/backward
- Speed control (0.5x, 1x, 2x, 5x)
- Jump to timestamp
- Filtering during replay
"""

import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
from dataclasses import dataclass

from .timeline_store import TimelineEventStore, TimelineEvent, get_timeline_store


class PlayState(Enum):
    """Playback states"""
    STOPPED = "stopped"
    PLAYING = "playing"
    PAUSED = "paused"


@dataclass
class ReplayStats:
    """Replay session statistics"""
    events_processed: int = 0
    current_timestamp: Optional[datetime] = None
    total_events: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    playback_speed: float = 1.0
    play_state: PlayState = PlayState.STOPPED


class TimelineReplayEngine:
    """
    Video-like replay engine for security event timelines
    
    Supports:
    - Play/pause/step controls
    - Playback speed adjustment (0.5x to 5x)
    - Jump to specific timestamp
    - Callbacks on event emission
    - Timeline filtering
    """
    
    def __init__(self, timeline_store: Optional[TimelineEventStore] = None):
        """
        Initialize replay engine
        
        Args:
            timeline_store: TimelineEventStore instance (uses singleton if not provided)
        """
        self.store = timeline_store or get_timeline_store()
        
        # Session state
        self.tenant_id: Optional[str] = None
        self.current_index = 0
        self.current_timestamp: Optional[datetime] = None
        self.events: List[TimelineEvent] = []
        
        # Playback controls
        self.state = PlayState.STOPPED
        self.playback_speed = 1.0  # 0.5x to 5x
        self.filters: Dict[str, Any] = {}
        
        # Thread management
        self.playback_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.lock = threading.RLock()
        
        # Callbacks
        self.on_event_callback: Optional[Callable[[TimelineEvent], None]] = None
        self.on_pause_callback: Optional[Callable[[datetime, int, int], None]] = None
        self.on_complete_callback: Optional[Callable[[], None]] = None
        
        # Statistics
        self.stats = ReplayStats()
    
    def load_range(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        filters: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Load events from time range
        
        Args:
            tenant_id: Tenant ID
            start_time: Start timestamp
            end_time: End timestamp
            filters: Optional filters (host_id, user_id, event_type, mitre_technique, etc.)
        
        Returns:
            Number of events loaded
        """
        with self.lock:
            self.tenant_id = tenant_id
            self.filters = filters or {}
            
            # Query events
            self.events = self.store.query_range(
                tenant_id, start_time, end_time, self.filters
            )
            
            # Sort by timestamp
            self.events.sort(key=lambda e: e.timestamp)
            
            # Reset playback
            self.current_index = 0
            self.current_timestamp = start_time if self.events else None
            self.state = PlayState.STOPPED
            
            # Update stats
            self.stats = ReplayStats(
                total_events=len(self.events),
                start_time=start_time,
                end_time=end_time,
                current_timestamp=self.current_timestamp,
            )
            
            return len(self.events)
    
    def play(self, speed: float = 1.0):
        """
        Start or resume playback
        
        Args:
            speed: Playback speed (0.5 to 5.0, default 1.0 is real-time)
        """
        with self.lock:
            if self.state == PlayState.PLAYING:
                return  # Already playing
            
            if not self.events:
                return  # No events loaded
            
            self.playback_speed = max(0.5, min(5.0, speed))
            self.state = PlayState.PLAYING
            self.pause_event.clear()
            self.stop_event.clear()
            
            # Start playback thread
            if self.playback_thread is None or not self.playback_thread.is_alive():
                self.playback_thread = threading.Thread(
                    target=self._playback_loop,
                    daemon=True
                )
                self.playback_thread.start()
    
    def pause(self):
        """Pause playback (can resume with play())"""
        with self.lock:
            if self.state == PlayState.PLAYING:
                self.state = PlayState.PAUSED
                self.pause_event.set()
                
                # Call pause callback with current state
                if self.on_pause_callback:
                    self.on_pause_callback(
                        self.current_timestamp,
                        self.current_index,
                        len(self.events)
                    )
    
    def stop(self):
        """Stop playback and reset"""
        with self.lock:
            self.state = PlayState.STOPPED
            self.stop_event.set()
            self.pause_event.clear()
            
            # Wait for thread to finish
            if self.playback_thread and self.playback_thread.is_alive():
                self.playback_thread.join(timeout=2.0)
                self.playback_thread = None
            
            self.current_index = 0
            if self.events:
                self.current_timestamp = self.events[0].timestamp
    
    def step_forward(self, count: int = 1) -> Optional[TimelineEvent]:
        """
        Step forward by N events
        
        Args:
            count: Number of events to step (default 1)
        
        Returns:
            Current event after stepping
        """
        with self.lock:
            if self.state == PlayState.PLAYING:
                self.pause()
            
            target_index = min(self.current_index + count, len(self.events) - 1)
            if target_index >= 0 and target_index < len(self.events):
                self.current_index = target_index
                event = self.events[self.current_index]
                self.current_timestamp = event.timestamp
                return event
            
            return None
    
    def step_backward(self, count: int = 1) -> Optional[TimelineEvent]:
        """
        Step backward by N events
        
        Args:
            count: Number of events to step (default 1)
        
        Returns:
            Current event after stepping
        """
        with self.lock:
            if self.state == PlayState.PLAYING:
                self.pause()
            
            target_index = max(self.current_index - count, 0)
            if target_index < len(self.events):
                self.current_index = target_index
                event = self.events[self.current_index]
                self.current_timestamp = event.timestamp
                return event
            
            return None
    
    def jump_to(self, timestamp: datetime) -> Optional[TimelineEvent]:
        """
        Jump to specific timestamp
        
        Args:
            timestamp: Target timestamp
        
        Returns:
            Event at or nearest to timestamp
        """
        with self.lock:
            if self.state == PlayState.PLAYING:
                self.pause()
            
            # Find event nearest to timestamp
            target_ts = timestamp.timestamp()
            best_index = 0
            best_diff = float('inf')
            
            for i, event in enumerate(self.events):
                event_ts = datetime.fromisoformat(
                    event.timestamp.replace('Z', '+00:00')
                ).timestamp()
                diff = abs(event_ts - target_ts)
                if diff < best_diff:
                    best_diff = diff
                    best_index = i
            
            if self.events:
                self.current_index = best_index
                event = self.events[self.current_index]
                self.current_timestamp = event.timestamp
                return event
            
            return None
    
    def set_filter(self, filter_key: str, filter_value: Any):
        """
        Update filter and reload events
        
        Args:
            filter_key: Filter key (host_id, user_id, process_id, event_type, etc.)
            filter_value: Filter value (None to remove filter)
        """
        with self.lock:
            if filter_value is None:
                self.filters.pop(filter_key, None)
            else:
                self.filters[filter_key] = filter_value
            
            # Reload events with new filter
            if self.tenant_id and self.stats.start_time and self.stats.end_time:
                self.load_range(
                    self.tenant_id,
                    self.stats.start_time,
                    self.stats.end_time,
                    self.filters
                )
    
    def set_event_callback(self, callback: Callable[[TimelineEvent], None]):
        """Set callback to be called for each event during playback"""
        self.on_event_callback = callback
    
    def set_pause_callback(self, callback: Callable[[datetime, int, int], None]):
        """Set callback called when paused (timestamp, current_index, total_events)"""
        self.on_pause_callback = callback
    
    def set_complete_callback(self, callback: Callable[[], None]):
        """Set callback called when playback completes"""
        self.on_complete_callback = callback
    
    def get_current_event(self) -> Optional[TimelineEvent]:
        """Get current event"""
        with self.lock:
            if 0 <= self.current_index < len(self.events):
                return self.events[self.current_index]
            return None
    
    def get_stats(self) -> ReplayStats:
        """Get replay statistics"""
        with self.lock:
            stats = ReplayStats(
                events_processed=self.current_index + 1,
                current_timestamp=self.current_timestamp,
                total_events=len(self.events),
                start_time=self.stats.start_time,
                end_time=self.stats.end_time,
                playback_speed=self.playback_speed,
                play_state=self.state,
            )
            return stats
    
    def _playback_loop(self):
        """Background thread that handles playback"""
        try:
            while not self.stop_event.is_set() and self.current_index < len(self.events):
                # Check if paused
                if self.pause_event.is_set():
                    self.pause_event.wait(timeout=0.1)
                    if self.stop_event.is_set():
                        break
                    continue
                
                # Get current event
                if self.current_index < len(self.events):
                    event = self.events[self.current_index]
                    
                    # Call callback
                    if self.on_event_callback:
                        try:
                            self.on_event_callback(event)
                        except Exception as e:
                            print(f"Callback error: {e}")
                    
                    # Calculate wait time based on speed
                    # In real implementation, would use event timestamp differences
                    wait_time = 0.1 / self.playback_speed  # 100ms per event at 1x
                    time.sleep(wait_time)
                
                # Move to next event
                with self.lock:
                    self.current_index += 1
                    if self.current_index < len(self.events):
                        self.current_timestamp = self.events[self.current_index].timestamp
        
        finally:
            # Mark as complete
            with self.lock:
                self.state = PlayState.STOPPED
                if self.on_complete_callback:
                    self.on_complete_callback()


# Singleton instance
_replay_engine: Optional[TimelineReplayEngine] = None


def get_replay_engine(timeline_store: Optional[TimelineEventStore] = None) -> TimelineReplayEngine:
    """Get or create replay engine singleton"""
    global _replay_engine
    if _replay_engine is None:
        _replay_engine = TimelineReplayEngine(timeline_store)
    return _replay_engine


def init_replay_engine(timeline_store: Optional[TimelineEventStore] = None) -> TimelineReplayEngine:
    """Initialize replay engine (for testing)"""
    global _replay_engine
    _replay_engine = TimelineReplayEngine(timeline_store)
    return _replay_engine
