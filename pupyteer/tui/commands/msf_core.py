"""MSF-style command handlers for Pupyteer TUI.

Provides Metasploit-like module interaction:
- use, set, unset, show options/modules/info
- search, exploit, run, back, reload

Each handler takes (tui: PupyteerTUI, args: list) -> dict result.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from pupyteer.tui.context import ModuleContext

logger = logging.getLogger("pupyteer.tui.commands.msf")


# ─── Helper ──────────────────────────────────────────────────────────

def _get_context(tui: Any) -> ModuleContext:
    """Ensure the TUI has a ModuleContext and return it."""
    ctx = getattr(tui, '_module_context', None)
    if ctx is not None:
        return ctx
    # Initialize lazily with the engine's registry
    engine = tui._engine
    registry = None
    if hasattr(engine, 'module_registry'):
        registry = engine.module_registry
    if registry is None:
        registry = getattr(engine, '_module_registry', None)
    if registry is None:
        from pupyteer.server.modules.registry import ModuleRegistry
        registry = ModuleRegistry(engine.config, engine.audit)
        registry.discover()
        engine._module_registry = registry
    if registry.count() == 0:
        registry.discover()
    ctx = ModuleContext(registry)
    tui._module_context = ctx
    return ctx


# ─── Module Selection ────────────────────────────────────────────────


async def use(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Select a module for use.

    Usage: use <module_name>

    Sets the active module from the registry.
    """
    ctx = _get_context(tui)

    if not args:
        return {"status": "error", "error": "Usage: use <module_name>"}

    module_name = args[0]
    result = ctx.use(module_name)

    if result["status"] == "ok":
        info = result["module"]
        tui.render_success(f"Using module {info['name']} ({info['category']})")
        tui.render_info(f"{info['description']}")
        if info.get('author'):
            tui.render_info(f"Author: {info['author']}")
    else:
        tui.render_error(result["error"])

    return result


# ─── Option Management ───────────────────────────────────────────────


async def set_option(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Set a module option value.

    Usage: set <option> <value>
    """
    ctx = _get_context(tui)

    if not ctx.has_active_module:
        tui.render_error("No active module. Use 'use <module>' first.")
        return {"status": "error", "error": "No active module"}

    if len(args) < 2:
        tui.render_error("Usage: set <option> <value>")
        return {"status": "error", "error": "Usage: set <option> <value>"}

    name = args[0]
    value = " ".join(args[1:])
    result = ctx.set_option(name, value)

    if result["status"] == "ok":
        tui.render_success(f"{name} => {value}")
    else:
        tui.render_error(result["error"])

    return result


async def unset_option(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Clear a module option.

    Usage: unset <option>
           unset all
    """
    ctx = _get_context(tui)

    if not ctx.has_active_module:
        tui.render_error("No active module. Use 'use <module>' first.")
        return {"status": "error", "error": "No active module"}

    if not args:
        tui.render_error("Usage: unset <option> | unset all")
        return {"status": "error", "error": "Usage: unset <option> | unset all"}

    if args[0].lower() == "all":
        for name in list(ctx.get_all_options().keys()):
            ctx.unset_option(name)
        tui.render_success("All options cleared")
        return {"status": "ok", "cleared": True}

    name = args[0]
    result = ctx.unset_option(name)

    if result["status"] == "ok":
        tui.render_success(f"{name} => (empty)")
    else:
        tui.render_error(result["error"])

    return result


# ─── Display Commands ────────────────────────────────────────────────


async def show_options(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Display active module options.

    Usage: show options

    Shows a table of options with name, current value, required, and description.
    """
    ctx = _get_context(tui)

    if not ctx.has_active_module:
        tui.render_error("No active module. Use 'use <module>' first.")
        return {"status": "error", "error": "No active module"}

    options = ctx.get_all_options()
    if not options:
        tui.render_info("No options for this module.")
        return {"status": "ok", "options": []}

    headers = ["Option", "Current Value", "Required", "Description"]
    rows = []
    for name, opt in sorted(options.items()):
        val = str(opt.get('value', '')) or '(empty)'
        req = 'true' if opt.get('required', False) else 'false'
        desc = opt.get('description', '') or ''
        rows.append([name, val, req, desc])

    tui.render_table(headers, rows)
    return {"status": "ok", "options": list(options.keys())}


async def show_modules(tui: Any, args: List[str]) -> Dict[str, Any]:
    """List all available modules grouped by category.

    Usage: show modules

    Displays modules organized by their category.
    """
    ctx = _get_context(tui)
    registry = ctx.registry
    modules = registry.list_all()
    failed = [h for h in registry.list_health() if h["state"] == "failed"]

    if not modules:
        tui.render_warning("No modules loaded. Run 'reload' to discover.")
        if failed:
            tui.render_warning(
                f"{len(failed)} module file(s) failed to load: "
                + ", ".join(h["name"] for h in failed[:5])
            )
        return {"status": "ok", "count": 0, "modules": []}

    # Group by category
    by_category: Dict[str, List[Dict]] = {}
    for m in modules:
        cat = m.get('category', 'unknown')
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(m)

    for category in sorted(by_category.keys()):
        mods = by_category[category]
        print(f"\n  {category.upper()} ({len(mods)}):")
        headers = ["Module", "Version", "Description"]
        rows = []
        for m in sorted(mods, key=lambda x: x['name']):
            rows.append([m['name'], m.get('version', '?'), m.get('description', '')[:40]])
        tui.render_table(headers, rows)

    if failed:
        tui.render_warning(
            f"{len(failed)} module(s) failed to load: "
            + ", ".join(h["name"] for h in failed[:5])
        )

    return {"status": "ok", "count": len(modules), "modules": modules}


async def show_info(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Show active module details.

    Usage: show info
    """
    ctx = _get_context(tui)

    if not ctx.has_active_module:
        tui.render_error("No active module. Use 'use <module>' first.")
        return {"status": "error", "error": "No active module"}

    module = ctx.module
    info = module.get_info()

    print(f"\n  {info['name']} ({info.get('category', 'unknown')})")
    print(f"    Version: {info.get('version', '?')}")
    print(f"    Author: {info.get('author', '?')}")
    print(f"    Description: {info.get('description', '?')}")
    if info.get('requirements'):
        print(f"    Requirements: {', '.join(info['requirements'])}")
    if info.get('compatible_systems'):
        print(f"    Compatible: {', '.join(info['compatible_systems'])}")

    options = ctx.get_all_options()
    if options:
        print(f"\n    Options:")
        for name, opt in sorted(options.items()):
            req = 'Required' if opt.get('required') else 'Optional'
            print(f"      {name} = {opt.get('value', '(empty)')}  [{req}]")

    return {"status": "ok", "info": info}


async def info(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Alias for show info."""
    return await show_info(tui, args)


# ─── Search ──────────────────────────────────────────────────────────


async def search(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Search modules by name, description, or category.

    Usage: search <query>
    """
    ctx = _get_context(tui)
    registry = ctx.registry

    if not args:
        tui.render_error("Usage: search <query>")
        return {"status": "error", "error": "Usage: search <query>"}

    query = " ".join(args).lower()
    modules = registry.list_all()

    results = []
    for m in modules:
        if (query in m.get('name', '').lower() or
            query in m.get('description', '').lower() or
            query in m.get('category', '').lower()):
            results.append(m)

    if not results:
        tui.render_info(f"No modules found matching '{query}'")
        return {"status": "ok", "count": 0, "query": query, "results": []}

    headers = ["Module", "Category", "Description"]
    rows = []
    for m in results:
        rows.append([m['name'], m.get('category', ''), m.get('description', '')[:40]])
    tui.render_table(headers, rows)
    print(f"\n  Found {len(results)} modules matching '{query}'")

    return {"status": "ok", "count": len(results), "query": query, "results": results}


# ─── Navigation ──────────────────────────────────────────────────────


async def back(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Clear active module and return to main context.

    Usage: back
    """
    ctx = _get_context(tui)
    if ctx.has_active_module:
        name = ctx.module_name
        ctx.clear()
        tui.render_success(f"Left module '{name}'. Back to main context.")
    else:
        tui.render_info("Already in main context.")
    return {"status": "ok"}


# ─── Execution ───────────────────────────────────────────────────────


async def exploit(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Execute active module (payload/listener modules).

    Usage: exploit

    Dispatches to the appropriate engine subsystem based on module category.
    """
    ctx = _get_context(tui)

    if not ctx.has_active_module:
        tui.render_error("No active module. Use 'use <module>' first.")
        return {"status": "error", "error": "No active module"}

    # Validate required options
    missing = ctx.validate_required()
    if missing:
        tui.render_error(f"Missing required options: {', '.join(missing)}")
        return {"status": "error", "error": f"Missing: {', '.join(missing)}"}

    module = ctx.module
    module_name = ctx.module_name
    category = module.category.value if hasattr(module.category, 'value') else str(module.category)
    effective_args = ctx.get_effective_args()

    tui.render_success(f"Exploiting with {module_name}...")

    # Dispatch based on category
    try:
        if category == 'payload':
            return await _dispatch_payload(tui, module_name, effective_args)
        elif category == 'listener':
            return await _dispatch_listener(tui, module_name, effective_args)
        elif category == 'evasion':
            return await _dispatch_evasion(tui, module_name, effective_args)
        else:
            # RECON, EXECUTION, FILE_OPS, RED_TEAM — all execute on session
            session_id = effective_args.get('SESSION')
            if not session_id:
                tui.render_error("SESSION option required for this module type.")
                return {"status": "error", "error": "SESSION option required"}

            return await _dispatch_module(tui, module_name, session_id, effective_args)

    except Exception as e:
        logger.exception("Module execution error")
        tui.render_error(f"Module execution failed: {e}")
        return {"status": "error", "error": str(e)}


async def run(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Execute active module (post modules).

    Usage: run

    Alias for exploit — Metasploit-like command for post-exploitation.
    """
    return await exploit(tui, args)


async def _dispatch_payload(tui: Any, module_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch a PAYLOAD module — build payload and start listener."""
    from pupyteer.payloads.manager import PayloadConfig, PayloadManager

    # Build payload configuration from options
    config = PayloadConfig(
        name=args.get('PAYLOAD_NAME', module_name),
        platform=args.get('PLATFORM', 'windows'),
        arch=args.get('ARCH', 'x64'),
        payload_type=args.get('PAYLOAD_TYPE', 'executable'),
        transport=args.get('TRANSPORT', 'tcp'),
        host=args.get('LHOST', '127.0.0.1'),
        port=int(args.get('LPORT', 8443)),
        profile=args.get('PROFILE', 'default'),
    )

    manager = PayloadManager(tui._engine.config, tui._engine.audit)
    try:
        metadata = await manager.build(config)
        if metadata.status == 'verified':
            tui.render_success(f"Payload built: {metadata.payload_id}")
            tui.render_info(f"Hash: {metadata.hash_sha256}")
            tui.render_info(f"Size: {metadata.size_bytes} bytes")
            tui.render_info(f"Path: {metadata.artifact_path}")
            # Start listener if requested
            if args.get('START_LISTENER', '').lower() in ('true', 'yes', '1'):
                await _start_listener(tui, config.transport, config.host, config.port)
            return {"status": "ok", "payload": metadata.to_dict()}
        else:
            tui.render_error(f"Payload build failed: {metadata.build_log}")
            return {"status": "error", "error": "Build failed", "log": metadata.build_log}
    except Exception as e:
        tui.render_error(f"Payload build error: {e}")
        return {"status": "error", "error": str(e)}


async def _dispatch_listener(tui: Any, module_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch a LISTENER module — start transport listener."""
    transport = args.get('TRANSPORT', 'tcp')
    host = args.get('LHOST', '127.0.0.1')
    port = int(args.get('LPORT', 8443))

    await _start_listener(tui, transport, host, port)
    return {"status": "ok", "listener": f"{transport}://{host}:{port}"}


async def _start_listener(tui: Any, transport: str, host: str, port: int) -> None:
    """Start a transport listener."""
    transports = tui._engine.transports
    try:
        # Find existing or start new
        existing = [t for t in transports.list() if t.get('name') == transport]
        if not existing:
            # Attempt to initialize transport
            await transports.initialize()
            tui.render_success(f"Listener started: {transport}://{host}:{port}")
        else:
            tui.render_info(f"Listener already active for {transport}")
    except Exception as e:
        tui.render_error(f"Failed to start listener: {e}")
        raise


async def _dispatch_evasion(tui: Any, module_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch an EVASION module — run evasion test."""
    from pupyteer.server.evasion.models import EvasionTestConfig
    from pupyteer.server.evasion.runner import EvasionTestRunner, RunnerConfig

    config = EvasionTestConfig(
        name=args.get('TEST_NAME', module_name),
        artifact_path=args.get('ARTIFACT_PATH', ''),
        artifact_hash_sha256=args.get('ARTIFACT_HASH', ''),
        environment=args.get('ENVIRONMENT', 'local'),
        controls=args.get('CONTROLS', '').split(',') if args.get('CONTROLS') else [],
        test_mode=True,
    )

    runner = EvasionTestRunner(tui._engine.config, tui._engine.audit, RunnerConfig(auto_obfuscate=False))
    await runner.initialize()

    try:
        result = await runner.run_with_profile(
            args.get('PROFILE', 'default'),
            config.artifact_path or '/dev/null',
            environment=config.environment,
        )
        tui.render_success(f"Evasion test completed: {result.test_id}")
        return {"status": "ok", "test": result.to_dict()}
    except Exception as e:
        tui.render_error(f"Evasion test failed: {e}")
        return {"status": "error", "error": str(e)}
    finally:
        await runner.shutdown()


async def _dispatch_module(tui: Any, module_name: str, session_id: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch a standard module — execute against a session."""
    # Get the session
    session = await tui._engine.sessions.get(session_id)
    if not session:
        tui.render_error(f"Session not found: {session_id}")
        return {"status": "error", "error": f"Session not found: {session_id}"}

    # Use the engine's module registry to execute
    registry = _get_context(tui).registry
    result = await registry.execute(module_name, session, args)

    if result.get('status') == 'ok':
        tui.render_success(f"Module executed successfully on {session_id}")
        if result.get('data'):
            print(f"  Data: {result['data']}")
    else:
        tui.render_error(f"Module execution failed: {result.get('error', 'unknown error')}")

    return result


# ─── Registry Management ─────────────────────────────────────────────


async def reload(tui: Any, args: List[str]) -> Dict[str, Any]:
    """Reload module registry.

    Usage: reload
    """
    ctx = _get_context(tui)
    registry = ctx.registry
    registry.discover()

    # Clear active module since the instance may be stale
    if ctx.has_active_module:
        ctx.clear()

    count = registry.count()
    tui.render_success(f"Module registry reloaded. {count} modules available.")
    return {"status": "ok", "count": count}


# ─── Command Mapping ─────────────────────────────────────────────────

COMMANDS: Dict[str, Any] = {
    "use": use,
    "set": set_option,
    "unset": unset_option,
    "show options": show_options,
    "show modules": show_modules,
    "show info": show_info,
    "info": info,
    "search": search,
    "back": back,
    "exploit": exploit,
    "run": run,
    "reload": reload,
}
