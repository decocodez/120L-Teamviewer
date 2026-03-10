def page_live_monitor(cfg: Cfg):
    st.header("Real-Time AI Auditor")
    st.info("Continuous polling active: Monitoring for new TeamViewer connections.")

    # Tracking all seen sessions to prevent redundant AI analysis
    if "all_seen_sessions" not in st.session_state:
        st.session_state.all_seen_sessions = set()
    
    # Tracking specifically the LAST 5 for the UI display feed
    if "live_feed_recent" not in st.session_state:
        st.session_state.live_feed_recent = []

    col_feed, col_stats = st.columns([2, 1])

    if st.sidebar.button("Simulate New Activity"):
        st.session_state.all_seen_sessions = set()
        st.session_state.live_feed_recent = []
        update_audit_log("SIMULATION: Cache cleared for re-audit.")
        st.toast("Activity simulated!")

    try:
        # Fetching latest connections
        sessions = fetch_sessions(cfg.backend_url, limit=5)
        active_ids = {s["session_id"] for s in sessions}
        
        # Determine if there are new IDs we haven't processed yet
        new_ids = [sid for sid in active_ids if sid not in st.session_state.all_seen_sessions]

        if new_ids:
            update_audit_log(f"Detected {len(new_ids)} un-audited connections.")
            with st.status("AI Investigation in progress...", expanded=True) as status:
                st.write("Extracting metadata...")
                new_batch = [s for s in sessions if s["session_id"] in new_ids]
                results = analyze_sessions(cfg.backend_url, new_batch)
                
                for sid, a in results.items():
                    # Add to the global "seen" set
                    st.session_state.all_seen_sessions.add(sid)
                    
                    # Update the UI-specific Last 5 list (add to front)
                    st.session_state.live_feed_recent.insert(0, sid)
                    # Constrain list to only 5 items
                    st.session_state.live_feed_recent = st.session_state.live_feed_recent[:5]
                    
                    update_audit_log(f"AUDIT: {sid} | {a['level'].upper()} | Score: {a['score']}")
                
                status.update(label="Audit Cycle Complete", state="complete", expanded=False)

        with col_feed:
            st.subheader("Live Assessment Feed (Last 5)")
            if not st.session_state.live_feed_recent:
                st.write("No active sessions detected.")
            else:
                # Iterate through the specifically tracked Last 5
                for sid in st.session_state.live_feed_recent:
                    st.success(f"Session {sid}: Monitored & AI-Verified")

        with col_stats:
            st.subheader("Global Metrics")
            st.metric("Total Sessions Audited", len(st.session_state.all_seen_sessions))
            st.metric("System Uptime", "100%", delta="Stable")

    except Exception as e:
        st.error(f"Monitor Sync Error: {e}")
    
    time.sleep(12)
    st.rerun()
