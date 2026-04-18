"""
Timeline API - FastAPI endpoints for attack timeline replay

Provides REST API for:
- Loading and replaying event timelines
- Querying specific events and correlations
- Forensic analysis operations
- Attack chain inspection
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Query, HTTPException, Body
from pydantic import BaseModel

from edr_behavior.timeline_store import (
    TimelineEventStore, TimelineEvent, EventMode,
    get_timeline_store, init_timeline_store
)
from edr_behavior.replay_engine import (
    TimelineReplayEngine, PlayState,
    get_replay_engine, init_replay_engine
)
from edr_behavior.attack_chain_correlator import (
    AttackChainCorrelator,
    get_correlator, init_correlator
)


# ============================================================================
# Pydantic Models
# ============================================================================

class TimelineEventRequest(BaseModel):
    """Request to add event to timeline"""
    timestamp: str
    event_id: str
    tenant_id: str
    host_id: str
    user_id: Optional[str] = None
    process_id: Optional[str] = None
    parent_process_id: Optional[str] = None
    process_name: str
    event_type: str
    severity: str
    source: str
    mitre_techniques: List[str] = []
    mitre_tactics: List[str] = []
    details: Dict[str, Any] = {}
    tags: List[str] = []


class TimelineQueryRequest(BaseModel):
    """Request to query timeline range"""
    tenant_id: str
    start_time: str  # ISO format
    end_time: str    # ISO format
    filters: Optional[Dict[str, Any]] = None


class ReplayControlRequest(BaseModel):
    """Request for replay control"""
    speed: Optional[float] = 1.0


class TimelineResponse(BaseModel):
    """Response with timeline event"""
    event_id: str
    timestamp: str
    host_id: str
    user_id: Optional[str]
    process_id: Optional[str]
    process_name: str
    event_type: str
    severity: str
    mitre_techniques: List[str]
    mitre_tactics: List[str]


class ReplayStatsResponse(BaseModel):
    """Response with replay statistics"""
    state: str
    events_processed: int
    total_events: int
    current_timestamp: Optional[str]
    playback_speed: float
    progress_percent: float


class AttackChainResponse(BaseModel):
    """Response with attack chain summary"""
    chain_id: str
    num_events: int
    severity: str
    total_anomaly_score: float
    start_timestamp: str
    end_timestamp: str
    tags: List[str]
    timeline: List[str]


# ============================================================================
# API Router
# ============================================================================

def create_timeline_router(
    timeline_store: Optional[TimelineEventStore] = None,
    replay_engine: Optional[TimelineReplayEngine] = None,
    correlator: Optional[AttackChainCorrelator] = None
) -> APIRouter:
    """
    Create timeline API router
    
    Args:
        timeline_store: Timeline store instance (uses singleton if not provided)
        replay_engine: Replay engine instance (uses singleton if not provided)
        correlator: Attack chain correlator instance (uses singleton if not provided)
    
    Returns:
        APIRouter instance
    """
    
    # Use singletons if not provided
    store = timeline_store or get_timeline_store()
    engine = replay_engine or get_replay_engine()
    corr = correlator or get_correlator()
    
    router = APIRouter(prefix="/timeline", tags=["timeline"])
    
    # ========================================================================
    # Timeline Event Management
    # ========================================================================
    
    @router.post("/events/add")
    async def add_timeline_event(event_req: TimelineEventRequest) -> Dict[str, str]:
        """Add event to timeline"""
        try:
            event = TimelineEvent(
                timestamp=event_req.timestamp,
                event_id=event_req.event_id,
                tenant_id=event_req.tenant_id,
                host_id=event_req.host_id,
                user_id=event_req.user_id,
                process_id=event_req.process_id,
                parent_process_id=event_req.parent_process_id,
                process_name=event_req.process_name,
                event_type=event_req.event_type,
                severity=event_req.severity,
                source=event_req.source,
                mitre_techniques=event_req.mitre_techniques,
                mitre_tactics=event_req.mitre_tactics,
                details=event_req.details,
                mode=EventMode.FORENSIC,
                tags=event_req.tags,
            )
            
            event_id = store.add_event(event)
            return {"event_id": event_id, "status": "added"}
        
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.get("/events/{event_id}")
    async def get_timeline_event(
        event_id: str,
        tenant_id: str = Query(...)
    ) -> Dict[str, Any]:
        """Get single timeline event"""
        event = store.get_event(tenant_id, event_id)
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
        return event.to_dict()
    
    @router.post("/events/query-range")
    async def query_timeline_range(query_req: TimelineQueryRequest) -> Dict[str, Any]:
        """Query events in time range"""
        try:
            start = datetime.fromisoformat(query_req.start_time.replace('Z', '+00:00'))
            end = datetime.fromisoformat(query_req.end_time.replace('Z', '+00:00'))
            
            events = store.query_range(
                query_req.tenant_id, start, end, query_req.filters
            )
            
            return {
                "count": len(events),
                "events": [e.to_dict() for e in events],
            }
        
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    # ========================================================================
    # Timeline Replay
    # ========================================================================
    
    @router.post("/replay/load")
    async def load_replay_range(query_req: TimelineQueryRequest) -> Dict[str, Any]:
        """Load events for replay"""
        try:
            start = datetime.fromisoformat(query_req.start_time.replace('Z', '+00:00'))
            end = datetime.fromisoformat(query_req.end_time.replace('Z', '+00:00'))
            
            count = engine.load_range(
                query_req.tenant_id, start, end, query_req.filters
            )
            
            stats = engine.get_stats()
            
            return {
                "events_loaded": count,
                "start_time": stats.start_time.isoformat() if stats.start_time else None,
                "end_time": stats.end_time.isoformat() if stats.end_time else None,
            }
        
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/replay/play")
    async def play_timeline(control: ReplayControlRequest) -> Dict[str, str]:
        """Start or resume timeline playback"""
        engine.play(speed=control.speed)
        return {"status": "playing", "speed": engine.playback_speed}
    
    @router.post("/replay/pause")
    async def pause_timeline() -> Dict[str, str]:
        """Pause timeline playback"""
        engine.pause()
        return {"status": "paused"}
    
    @router.post("/replay/stop")
    async def stop_timeline() -> Dict[str, str]:
        """Stop timeline playback"""
        engine.stop()
        return {"status": "stopped"}
    
    @router.post("/replay/step-forward")
    async def step_forward(count: int = Query(1)) -> Dict[str, Any]:
        """Step forward in timeline"""
        event = engine.step_forward(count)
        return {
            "status": "ok",
            "event": event.to_dict() if event else None,
            "current_index": engine.current_index,
            "total_events": len(engine.events),
        }
    
    @router.post("/replay/step-backward")
    async def step_backward(count: int = Query(1)) -> Dict[str, Any]:
        """Step backward in timeline"""
        event = engine.step_backward(count)
        return {
            "status": "ok",
            "event": event.to_dict() if event else None,
            "current_index": engine.current_index,
            "total_events": len(engine.events),
        }
    
    @router.post("/replay/jump-to")
    async def jump_to_timestamp(timestamp: str = Body(...)) -> Dict[str, Any]:
        """Jump to specific timestamp"""
        try:
            ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            event = engine.jump_to(ts)
            
            return {
                "status": "ok",
                "event": event.to_dict() if event else None,
                "current_index": engine.current_index,
                "total_events": len(engine.events),
            }
        
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.get("/replay/stats")
    async def get_replay_stats() -> ReplayStatsResponse:
        """Get current replay statistics"""
        stats = engine.get_stats()
        progress = 0.0
        if stats.total_events > 0:
            progress = (stats.events_processed / stats.total_events) * 100
        
        return ReplayStatsResponse(
            state=stats.play_state.value,
            events_processed=stats.events_processed,
            total_events=stats.total_events,
            current_timestamp=stats.current_timestamp.isoformat() if stats.current_timestamp else None,
            playback_speed=stats.playback_speed,
            progress_percent=progress,
        )
    
    @router.post("/replay/filter")
    async def set_replay_filter(
        filter_key: str = Query(...),
        filter_value: Optional[str] = Query(None)
    ) -> Dict[str, str]:
        """Update filter during replay"""
        engine.set_filter(filter_key, filter_value)
        return {"status": "filter_updated", "filter_key": filter_key}
    
    # ========================================================================
    # Attack Chain Correlation
    # ========================================================================
    
    @router.post("/correlate/events")
    async def correlate_events(
        tenant_id: str = Query(...),
        event_ids: List[str] = Body(...)
    ) -> Dict[str, Any]:
        """Correlate specific events into attack chain"""
        try:
            events = []
            for event_id in event_ids:
                event = store.get_event(tenant_id, event_id)
                if event:
                    events.append(event)
            
            if not events:
                raise HTTPException(status_code=400, detail="No events found")
            
            chain = corr.correlate_events(tenant_id, events)
            
            return chain.to_dict()
        
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/correlate/process-tree")
    async def correlate_by_process_tree(
        tenant_id: str = Query(...),
        process_id: str = Query(...),
        start_time: str = Query(...),
        end_time: str = Query(...)
    ) -> Dict[str, Any]:
        """Correlate events by process tree"""
        try:
            start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            
            chain = corr.correlate_by_process_tree(
                tenant_id, process_id, start, end
            )
            
            return chain.to_dict()
        
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.get("/attack-chains/{chain_id}")
    async def get_attack_chain(chain_id: str) -> Dict[str, Any]:
        """Get attack chain by ID"""
        chain = corr.get_chain(chain_id)
        if not chain:
            raise HTTPException(status_code=404, detail="Chain not found")
        return chain.to_dict()
    
    @router.get("/attack-chains")
    async def list_attack_chains(tenant_id: Optional[str] = Query(None)) -> Dict[str, Any]:
        """List attack chains"""
        chains = corr.get_chains(tenant_id)
        return {
            "count": len(chains),
            "chains": [c.to_dict() for c in chains],
        }
    
    @router.get("/attack-chains/severity/{severity}")
    async def get_chains_by_severity(
        severity: str,
        tenant_id: str = Query(...)
    ) -> Dict[str, Any]:
        """Get attack chains by severity"""
        chains = corr.get_chains_by_severity(tenant_id, severity)
        return {
            "count": len(chains),
            "chains": [c.to_dict() for c in chains],
        }
    
    # ========================================================================
    # Timeline Statistics
    # ========================================================================
    
    @router.get("/stats")
    async def get_timeline_stats(tenant_id: Optional[str] = Query(None)) -> Dict[str, Any]:
        """Get timeline statistics"""
        stats = store.get_stats(tenant_id)
        return stats
    
    @router.post("/clear")
    async def clear_timeline(tenant_id: Optional[str] = Query(None)) -> Dict[str, str]:
        """Clear timeline events"""
        store.clear(tenant_id)
        corr.clear(tenant_id)
        return {"status": "cleared"}
    
    return router


# ============================================================================
# FastAPI Integration
# ============================================================================

def include_timeline_routes(app, **kwargs):
    """Include timeline routes in FastAPI app"""
    router = create_timeline_router(**kwargs)
    app.include_router(router)
