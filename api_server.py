"""
REST API Server for Security Scanner Dashboard
Provides real-time monitoring and scan management via FastAPI
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime
import json
import asyncio
import uuid
from collections import defaultdict

from scanner import run_comprehensive_scan
from vulnerability_scanner import VulnerabilityScanner
from auto_fix import AutoFix
from config import get_config
from logger import get_logger

logger = get_logger()

# Initialize FastAPI app
app = FastAPI(
    title="Security Scanner API",
    description="Advanced security scanner with real-time monitoring",
    version="3.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
active_scans = {}
scan_history = []
websocket_connections = []


# Pydantic Models
class ScanRequest(BaseModel):
    """Request model for initiating a scan."""
    path: str
    enable_ai: bool = True
    ai_provider: str = "gemini"
    enable_vulnerabilities: bool = True
    output_format: str = "json"


class AutoFixRequest(BaseModel):
    """Request model for auto-fix."""
    path: str
    fix_types: Optional[List[str]] = None
    interactive: bool = False


class ScanResponse(BaseModel):
    """Response model for scan initiation."""
    scan_id: str
    status: str
    message: str


class ScanStatus(BaseModel):
    """Response model for scan status."""
    scan_id: str
    status: str
    progress: int
    start_time: str
    end_time: Optional[str]
    results: Optional[Dict]


class DashboardStats(BaseModel):
    """Dashboard statistics."""
    total_scans: int
    active_scans: int
    total_secrets_found: int
    total_vulnerabilities_found: int
    critical_vulnerabilities: int
    recent_scans: List[Dict]


# WebSocket Connection Manager
class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection."""
        self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to send message: {e}")


manager = ConnectionManager()


# Background Tasks
async def run_scan_task(scan_id: str, request: ScanRequest):
    """Run security scan as background task."""
    try:
        # Update scan status
        active_scans[scan_id]['status'] = 'running'
        active_scans[scan_id]['progress'] = 10

        # Broadcast progress
        await manager.broadcast({
            'type': 'scan_progress',
            'scan_id': scan_id,
            'progress': 10,
            'message': 'Starting scan...'
        })

        # Run the scan
        secrets, vulnerabilities, stats = run_comprehensive_scan(
            path=request.path,
            enable_ai=request.enable_ai,
            ai_provider=request.ai_provider,
            enable_vulnerabilities=request.enable_vulnerabilities
        )

        # Update progress
        active_scans[scan_id]['progress'] = 90

        # Prepare results
        results = {
            'secrets': [
                {
                    'type': s.get('type', 'Unknown'),
                    'file_path': s.get('file_path', ''),
                    'line_number': s.get('line_number', 0),
                    'matched_text': s.get('matched_text', '')[:100],  # Truncate
                    'ai_verified': s.get('ai_verified', False)
                }
                for s in secrets
            ],
            'vulnerabilities': [
                {
                    'name': v.name,
                    'severity': v.severity,
                    'category': v.category,
                    'cwe': v.cwe,
                    'owasp': v.owasp,
                    'file_path': v.file_path,
                    'line_number': v.line_number,
                    'description': v.description,
                    'recommendation': v.recommendation
                }
                for v in vulnerabilities
            ],
            'statistics': stats
        }

        # Update scan
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['progress'] = 100
        active_scans[scan_id]['end_time'] = datetime.now().isoformat()
        active_scans[scan_id]['results'] = results

        # Add to history
        scan_history.append({
            'scan_id': scan_id,
            'path': request.path,
            'start_time': active_scans[scan_id]['start_time'],
            'end_time': active_scans[scan_id]['end_time'],
            'total_secrets': len(secrets),
            'total_vulnerabilities': len(vulnerabilities),
            'critical_vulnerabilities': len([v for v in vulnerabilities if v.severity == 'critical'])
        })

        # Broadcast completion
        await manager.broadcast({
            'type': 'scan_complete',
            'scan_id': scan_id,
            'results': results
        })

        logger.info(f"Scan {scan_id} completed successfully")

    except Exception as e:
        logger.exception(f"Scan {scan_id} failed")
        active_scans[scan_id]['status'] = 'failed'
        active_scans[scan_id]['error'] = str(e)
        active_scans[scan_id]['end_time'] = datetime.now().isoformat()

        # Broadcast error
        await manager.broadcast({
            'type': 'scan_error',
            'scan_id': scan_id,
            'error': str(e)
        })


# API Endpoints
@app.get("/")
async def root():
    """Root endpoint - API information."""
    return {
        "name": "Security Scanner API",
        "version": "3.0.0",
        "description": "Advanced security scanner with real-time monitoring",
        "endpoints": {
            "POST /api/v1/scan": "Start a new security scan",
            "GET /api/v1/scan/{scan_id}": "Get scan status and results",
            "GET /api/v1/scans": "List all scans",
            "POST /api/v1/auto-fix": "Run auto-fix on code",
            "GET /api/v1/dashboard/stats": "Get dashboard statistics",
            "GET /api/v1/health": "Health check",
            "WebSocket /ws": "Real-time updates"
        }
    }


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_scans": len(active_scans),
        "websocket_connections": len(manager.active_connections)
    }


@app.post("/api/v1/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new security scan.

    Args:
        request: Scan configuration
        background_tasks: FastAPI background tasks

    Returns:
        Scan response with scan_id
    """
    # Validate path
    if not Path(request.path).exists():
        raise HTTPException(status_code=400, detail=f"Path not found: {request.path}")

    # Generate scan ID
    scan_id = str(uuid.uuid4())

    # Initialize scan
    active_scans[scan_id] = {
        'scan_id': scan_id,
        'path': request.path,
        'status': 'queued',
        'progress': 0,
        'start_time': datetime.now().isoformat(),
        'end_time': None,
        'results': None
    }

    # Add background task
    background_tasks.add_task(run_scan_task, scan_id, request)

    logger.info(f"Started scan {scan_id} for path: {request.path}")

    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Scan initiated for {request.path}"
    )


@app.get("/api/v1/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """
    Get status and results of a specific scan.

    Args:
        scan_id: Unique scan identifier

    Returns:
        Scan status and results
    """
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    scan = active_scans[scan_id]

    return ScanStatus(
        scan_id=scan_id,
        status=scan['status'],
        progress=scan['progress'],
        start_time=scan['start_time'],
        end_time=scan.get('end_time'),
        results=scan.get('results')
    )


@app.get("/api/v1/scans")
async def list_scans(limit: int = 50, offset: int = 0):
    """
    List all scans (active and completed).

    Args:
        limit: Maximum number of scans to return
        offset: Number of scans to skip

    Returns:
        List of scans
    """
    all_scans = list(active_scans.values()) + scan_history
    all_scans.sort(key=lambda x: x.get('start_time', ''), reverse=True)

    return {
        "total": len(all_scans),
        "scans": all_scans[offset:offset + limit]
    }


@app.post("/api/v1/auto-fix")
async def auto_fix(request: AutoFixRequest):
    """
    Run auto-fix on code.

    Args:
        request: Auto-fix configuration

    Returns:
        Auto-fix results
    """
    try:
        # Validate path
        if not Path(request.path).exists():
            raise HTTPException(status_code=400, detail=f"Path not found: {request.path}")

        # Run auto-fix
        auto_fix_engine = AutoFix(interactive=request.interactive)

        if Path(request.path).is_file():
            result = auto_fix_engine.fix_file(request.path, request.fix_types)
        else:
            from auto_fix import auto_fix_directory
            result = auto_fix_directory(
                directory=request.path,
                fix_types=request.fix_types,
                interactive=request.interactive
            )

        return {
            "success": True,
            "path": request.path,
            "fixes_applied": result.get('applied', 0) if isinstance(result, dict) else len(result.get('fixes', [])),
            "details": result
        }

    except Exception as e:
        logger.exception("Auto-fix failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """
    Get dashboard statistics.

    Returns:
        Dashboard statistics
    """
    total_secrets = sum(
        len(scan.get('results', {}).get('secrets', []))
        for scan in active_scans.values()
        if scan.get('results')
    )

    total_vulnerabilities = sum(
        len(scan.get('results', {}).get('vulnerabilities', []))
        for scan in active_scans.values()
        if scan.get('results')
    )

    critical_vulnerabilities = sum(
        len([v for v in scan.get('results', {}).get('vulnerabilities', []) if v.get('severity') == 'critical'])
        for scan in active_scans.values()
        if scan.get('results')
    )

    # Recent scans (last 10)
    recent = list(active_scans.values()) + scan_history
    recent.sort(key=lambda x: x.get('start_time', ''), reverse=True)
    recent_scans = recent[:10]

    return DashboardStats(
        total_scans=len(active_scans) + len(scan_history),
        active_scans=len([s for s in active_scans.values() if s['status'] == 'running']),
        total_secrets_found=total_secrets,
        total_vulnerabilities_found=total_vulnerabilities,
        critical_vulnerabilities=critical_vulnerabilities,
        recent_scans=recent_scans
    )


@app.get("/api/v1/reports/{scan_id}")
async def get_report(scan_id: str, format: str = "json"):
    """
    Get scan report in specified format.

    Args:
        scan_id: Unique scan identifier
        format: Report format (json, html, markdown)

    Returns:
        Scan report
    """
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    scan = active_scans[scan_id]

    if scan['status'] != 'completed':
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    if format == "json":
        return JSONResponse(content=scan['results'])
    elif format == "html":
        # Check if HTML report exists
        html_path = Path(f"output/report_{scan_id}.html")
        if html_path.exists():
            return FileResponse(html_path, media_type="text/html")
        else:
            raise HTTPException(status_code=404, detail="HTML report not found")
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time updates.

    Sends updates about:
    - Scan progress
    - Scan completion
    - New vulnerabilities found
    - System statistics
    """
    await manager.connect(websocket)

    try:
        # Send initial connection message
        await websocket.send_json({
            "type": "connection",
            "message": "Connected to Security Scanner API",
            "timestamp": datetime.now().isoformat()
        })

        # Keep connection alive and send periodic updates
        while True:
            try:
                # Wait for client messages (ping/pong)
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({
                    "type": "heartbeat",
                    "timestamp": datetime.now().isoformat()
                })

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


# Startup/Shutdown Events
@app.on_event("startup")
async def startup_event():
    """Initialize API server on startup."""
    logger.info("Security Scanner API starting up...")
    logger.info("API server ready at http://localhost:8000")
    logger.info("API docs available at http://localhost:8000/docs")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Security Scanner API shutting down...")
    # Close all WebSocket connections
    for connection in manager.active_connections:
        await connection.close()


if __name__ == "__main__":
    import uvicorn

    # Run the server
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
