# 500-Node Testnet Test Plan

## Version Information

- **saorsa-node**: v0.1.0
- **saorsa-core**: v0.7.6
- **Target**: 500 nodes across 5 Digital Ocean workers

## saorsa-core 0.7.6 Changes Summary

### Major Features: Enhanced Security Metrics & Enforcement

#### New in 0.7.6
| Feature | Description |
|---------|-------------|
| `trust_threshold_violations_total` | Trust threshold violation counter |
| `low_trust_nodes_current` | Current count of nodes below trust threshold |
| `enforcement_mode_strict` | Enforcement mode status (permissive/strict) |
| `close_group_failure_by_type` | Close group failures categorized by type |
| `eviction_by_reason` severity | Low trust evictions bucketed (critical/severe/moderate) |

#### New in 0.7.5
| Feature | Description |
|---------|-------------|
| `ip_diversity_rejections_total` | IPv4/IPv6 diversity enforcement rejections |
| `geographic_diversity_rejections_total` | Geographic diversity enforcement rejections |
| `nodes_per_region` | Node counts per geographic region |
| Dynamic per-IP limits | 0.5% of network size formula (max 50 nodes/IP) |

### Major Features (0.7.4): S/Kademlia Security Production Readiness

#### New Security Modules
| Module | Description |
|--------|-------------|
| `sybil_detector.rs` | Sybil attack detection and scoring |
| `collusion_detector.rs` | Witness collusion pattern detection |
| `authenticated_sibling_broadcast.rs` | Authenticated sibling list broadcasts |
| `close_group_validator.rs` | Close group consensus validation |
| `data_integrity_monitor.rs` | Continuous data integrity verification |
| `security_coordinator.rs` | Unified security orchestration |

#### New Metrics System (60+ Prometheus Metrics)
| Category | Metrics Count | Examples |
|----------|---------------|----------|
| Security | 20+ | eclipse_score, sybil_score, collusion_score, diversity_rejections |
| DHT Health | 12+ | routing_table_size, replication_health, lookup_latency |
| Trust | 12+ | eigentrust_avg, witness_receipts, interactions, low_trust_nodes, enforcement_mode |
| Placement | 10+ | geographic_diversity, load_balance_score, capacity, nodes_per_region |
| Close Group | 6+ | close_group_failure_by_type, validations, consensus_failures |

#### Enhanced S/Kademlia
- Parallel sibling broadcast validation
- BFT consensus mode for high-threat situations
- Adversarial testing infrastructure

### Bug Fixes from 0.7.3
- Routing maintenance module (eviction, liveness, refresh)
- Weighted shard distribution favoring headless devices
- Deadlock fix in storage API functions

---

## Phase 1: Infrastructure Validation

### 1.1 Bootstrap Node Health
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Bootstrap connectivity | Bootstrap nodes accessible | TCP/UDP 12000 responds |
| TLS handshake | PQC key exchange works | ML-KEM-768 completes |
| Health endpoint | /health returns OK | HTTP 200, all components healthy |
| Metrics endpoint | /metrics returns data | Prometheus format valid |
| Security dashboard | Security status accessible | `dht_security_*` metrics exported |

### 1.2 Worker Node Deployment
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Cloud-init execution | Worker VMs bootstrap correctly | All 100 nodes per worker start |
| Systemd services | All node services running | `systemctl status saorsa-node-*` shows active |
| Resource limits | Memory/CPU limits enforced | < 350MB per node |
| Log collection | Logs accessible | `/var/log/saorsa/node-*.log` populated |

---

## Phase 2: Network Formation Tests

### 2.1 DHT Formation
| Metric | Target | Measurement |
|--------|--------|-------------|
| Time to 500 nodes | < 10 minutes | All nodes report `dht_routing_table_size > 0` |
| Routing table size | 8-20 peers average | `dht_routing_table_size` |
| Bucket fullness | > 50% average | `dht_routing_table_bucket_fullness` |
| Geographic diversity | 3+ regions | `dht_placement_regions_covered` |

### 2.2 Node Discovery & Maintenance
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Bucket refresh | Periodic refresh works | `dht_bucket_refresh_total` increases |
| Liveness checking | Dead nodes detected | `dht_liveness_failures_total` > 0 when nodes die |
| Node eviction | Misbehaving nodes removed | `dht_security_nodes_evicted_total` correlates |

### 2.3 Sibling Broadcast (NEW in 0.7.4)
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Sibling list propagation | Authenticated broadcasts work | `dht_security_sibling_broadcasts_validated_total` increases |
| Sibling overlap | Consistent sibling views | `dht_security_sibling_overlap_ratio` > 0.8 |
| Broadcast rejection | Invalid broadcasts rejected | `dht_security_sibling_broadcasts_rejected_total` for bad inputs |

### 2.4 Connection Stability
| Metric | Target | Measurement |
|--------|--------|-------------|
| Active connections | 8-20 per node | Active connection count |
| Connection success rate | > 95% | Connection attempts vs failures |
| Keepalive success | > 99% | No unexpected disconnections |

---

## Phase 3: Payment System Tests

### 3.1 Quote Generation
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Quote creation | Node generates valid quotes | `PaymentQuote` returned |
| Quote signing | Quotes cryptographically signed | Signature verifies |
| Quote pricing | Price varies with capacity | Higher storage = higher price |

### 3.2 Payment Metrics
| Metric | Expected Behavior |
|--------|-------------------|
| `quoting_payments_received_total` | Increases with payments |
| `quoting_records_stored_total` | Increases with data storage |
| `quoting_live_time_hours` | Matches node uptime |
| `quoting_network_size` | Reflects estimated network |

### 3.3 EVM Integration
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Rewards address validation | Valid 0x addresses accepted | No errors on startup |
| Network selection | Arbitrum Sepolia for testnet | Correct chain ID |
| Quote verification | Quotes compatible with autonomi | Client can verify |

---

## Phase 4: Data Operations Tests

### 4.1 Storage Operations
| Operation | Target Latency | Success Rate |
|-----------|----------------|--------------|
| PUT (1KB) | < 500ms | > 99% |
| PUT (1MB) | < 2s | > 99% |
| GET (1KB) | < 200ms | > 99% |
| GET (1MB) | < 1s | > 99% |

### 4.2 DHT Performance Metrics
| Metric | Target |
|--------|--------|
| `dht_lookup_latency_p50_ms` | < 100ms |
| `dht_lookup_latency_p95_ms` | < 500ms |
| `dht_lookup_latency_p99_ms` | < 1s |
| `dht_success_rate` | > 99% |
| `dht_lookup_hops_avg` | < 6 |

### 4.3 Replication & Placement
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| K-value replication | Data on K nodes | `dht_replication_factor` = K |
| Replication health | Good replica coverage | `dht_replication_health` > 0.9 |
| Load balancing | Even distribution | `dht_placement_load_balance_score` > 0.7 |
| Geographic diversity | Multi-region | `dht_placement_geographic_diversity` > 0.5 |

### 4.4 Data Integrity (NEW in 0.7.4)
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Integrity monitoring | Continuous verification | `data_integrity_checks_total` increases |
| Corruption detection | Bad data flagged | `data_integrity_failures_total` = 0 (no corruption) |
| Audit success | Storage audits pass | `dht_placement_audit_failures_total` = 0 |

---

## Phase 5: Security Tests (MAJOR UPDATE in 0.7.4)

### 5.1 Attack Detection Metrics
| Metric | Healthy Range | Alert Threshold |
|--------|---------------|-----------------|
| `dht_security_eclipse_score` | 0.0 - 0.2 | > 0.5 |
| `dht_security_sybil_score` | 0.0 - 0.2 | > 0.5 |
| `dht_security_collusion_score` | 0.0 - 0.2 | > 0.5 |
| `dht_security_routing_manipulation_score` | 0.0 - 0.1 | > 0.3 |

### 5.2 Sybil Resistance
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Node age verification | New nodes restricted | Age < 1hr cannot replicate |
| Sybil detection | Fake nodes identified | `dht_security_sybil_nodes_detected_total` > 0 for attacks |
| Trust accumulation | Trust increases over time | `dht_trust_eigentrust_avg` increases with uptime |
| Low trust nodes | Flagged appropriately | `dht_trust_low_trust_nodes` < 10% of network |

### 5.3 Eclipse Attack Prevention
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Routing table diversity | No subnet domination | Max 20% from same /24 subnet |
| Eclipse detection | Attacks identified | `dht_security_eclipse_attempts_total` logged |
| Recovery | Network self-heals | Eclipse score returns to < 0.2 after attack |

### 5.4 Collusion Detection (NEW in 0.7.4)
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Witness independence | Witnesses not colluding | `dht_security_collusion_score` < 0.2 |
| Group detection | Colluding groups found | `dht_security_collusion_groups_detected_total` > 0 for attacks |
| Behavioral patterns | Coordinated behavior flagged | Pattern detection triggers alerts |

### 5.5 Close Group Validation (NEW in 0.7.4)
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Consensus validation | Close groups agree | `dht_security_close_group_validations_total` increases |
| Consensus failures | Disagreements logged | `dht_security_close_group_consensus_failures_total` tracked |
| Witness validation | Witnesses verify operations | `dht_security_witness_validations_total` > 0 |

### 5.6 BFT Mode (NEW in 0.7.4)
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Mode detection | High threat triggers BFT | `dht_security_bft_mode_active` = 1 when threatened |
| Escalation counting | Escalations tracked | `dht_security_bft_escalations_total` logged |
| De-escalation | Returns to normal | BFT mode deactivates when threat passes |

### 5.7 Trust & Reputation (NEW in 0.7.4)
| Metric | Target |
|--------|--------|
| `dht_trust_eigentrust_avg` | > 0.7 |
| `dht_trust_eigentrust_min` | > 0.3 |
| `dht_trust_witness_receipts_verified_total` | Increases with operations |
| `dht_trust_positive_interactions_total` | >> negative_interactions |

### 5.8 IP Diversity Enforcement (NEW in 0.7.5)
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| IPv4 diversity limits | IPv4 nodes limited per IP address | `ip_diversity_rejections_total` increases when exceeding limit |
| IPv6 diversity limits | IPv6 nodes limited per /64 subnet | Same limits apply across IPv6 subnets |
| Dynamic scaling | Limits scale with network size | 0.5% formula enforced (max 50 nodes/IP) |
| Bypass prevention | IPv4 bypass vulnerability closed | No IPv4 exemptions from diversity checks |

| Metric | Healthy Range | Alert Threshold |
|--------|---------------|-----------------|
| `ip_diversity_rejections_total` (rate) | < 1/min | > 10/min (possible attack) |
| Max nodes per IP | ≤ 50 | > 50 (limit breached) |

### 5.9 Geographic Diversity Enforcement (NEW in 0.7.5)
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Region limits | Max nodes per region enforced | `geographic_diversity_rejections_total` increases for excess |
| Region tracking | Node counts tracked per region | `nodes_per_region` shows distribution |
| Multi-region coverage | Network spans multiple regions | At least 3 regions represented |
| Load balancing | Even distribution across regions | No region > 40% of network |

| Metric | Healthy Range | Alert Threshold |
|--------|---------------|-----------------|
| `geographic_diversity_rejections_total` (rate) | < 1/min | > 10/min |
| `nodes_per_region{region="..."}` | Even distribution | Single region > 40% |
| Regions covered | ≥ 3 | < 3 regions |

### 5.10 Trust Enforcement (NEW in 0.7.6)
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Trust violations | Low trust nodes flagged | `trust_threshold_violations_total` tracked |
| Low trust count | Current low trust count accurate | `low_trust_nodes_current` < 10% of network |
| Severity bucketing | Evictions categorized by severity | `eviction_by_reason{reason="low_trust_*"}` tracked |
| Critical evictions | Trust < 0.05 marked critical | `eviction_by_reason{reason="low_trust_critical"}` |
| Severe evictions | Trust 0.05-0.10 marked severe | `eviction_by_reason{reason="low_trust_severe"}` |
| Moderate evictions | Trust 0.10+ marked moderate | `eviction_by_reason{reason="low_trust_moderate"}` |
| Enforcement mode toggle | Strict mode activates under threat | `enforcement_mode_strict` = 1 when under attack |

| Metric | Healthy Range | Alert Threshold |
|--------|---------------|-----------------|
| `low_trust_nodes_current` | < 5% of network | > 10% of network |
| `trust_threshold_violations_total` (rate) | < 5/min | > 10/min |
| `enforcement_mode_strict` | 0 (permissive) | 1 (strict - investigate!) |

### 5.12 Close Group Failure Analysis (NEW in 0.7.6)
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Failure type breakdown | Failures categorized by type | `close_group_failure_by_type` tracked |
| NotInCloseGroup | Wrong close group membership detected | Logged when node claims wrong group |
| LowTrustScore | Trust-based rejection | Correlates with trust violation metrics |
| InsufficientGeographicDiversity | Geographic diversity failure | Correlates with geo rejection metrics |
| SuspectedCollusion | Collusion pattern detected | Critical alert triggered |
| AttackModeTriggered | Attack detection escalation | Correlates with BFT mode |

| Failure Type | Description | Expected Frequency |
|--------------|-------------|-------------------|
| `NotInCloseGroup` | Node not in calculated close group | Rare (< 1/hr) |
| `LowTrustScore` | Node below trust threshold | Occasional during attacks |
| `InsufficientGeographicDiversity` | Geographic concentration | Occasional |
| `SuspectedCollusion` | Coordinated behavior detected | Rare (attack indicator) |
| `AttackModeTriggered` | Security escalation | Rare (critical alert) |

---

## Phase 6: Performance Benchmarks

### 6.1 Throughput Tests
| Scenario | Target |
|----------|--------|
| Concurrent PUTs (10 clients) | > 100 ops/sec aggregate |
| Concurrent GETs (10 clients) | > 500 ops/sec aggregate |
| Mixed workload (70% GET, 30% PUT) | > 300 ops/sec aggregate |

### 6.2 Resource Utilization
| Resource | Per-Node Limit | Network Total |
|----------|----------------|---------------|
| Memory | 350 MB | 175 GB |
| CPU | 15% | 750% (7.5 cores) |
| Bandwidth | 10 Mbps | 5 Gbps |
| Disk IOPS | 100 | 50,000 |

---

## Phase 7: Chaos Engineering

### 7.1 Node Failures
| Test | Method | Recovery Target |
|------|--------|-----------------|
| Single node crash | Kill process | Data still retrievable |
| Worker dropout | Stop 100 nodes | DHT reforms < 5 min |
| Rolling restart | Restart 10% at a time | Zero downtime |

### 7.2 Network Degradation
| Test | Method | Tolerance |
|------|--------|-----------|
| Latency injection | Add 200ms delay | Operations still succeed |
| Packet loss | Drop 5% packets | Retry logic handles |
| Bandwidth throttle | Limit to 1 Mbps | Graceful degradation |

### 7.3 Adversarial Testing (NEW in 0.7.4)
| Test | Method | Detection Target |
|------|--------|------------------|
| Sybil injection | Add 50 fake nodes | `dht_security_sybil_score` increases |
| Eclipse attempt | Concentrate routing | `dht_security_eclipse_score` increases |
| Collusion simulation | Coordinate 10 nodes | `dht_security_collusion_score` increases |
| Data manipulation | Send invalid data | Data integrity checks fail |

---

## Monitoring & Alerting

### Critical Alerts (P1 - Immediate Action)
| Alert | Condition | Action |
|-------|-----------|--------|
| BFT Mode Active | `dht_security_bft_mode_active == 1` | Investigate attack |
| Eclipse Attack | `dht_security_eclipse_score > 0.7` | Review routing tables |
| Sybil Attack | `dht_security_sybil_score > 0.7` | Identify fake nodes |
| Data Integrity | `data_integrity_failures_total > 0` | Investigate corruption |
| Node Count Drop | Count < 400 | Check worker health |

### Warning Alerts (P2 - Monitor Closely)
| Alert | Condition |
|-------|-----------|
| Collusion Detected | `dht_security_collusion_score > 0.5` |
| High Churn | `dht_security_churn_rate_5m > 0.3` |
| Low Trust Average | `dht_trust_eigentrust_avg < 0.5` |
| Latency Degraded | `dht_lookup_latency_p95_ms > 1000` |
| Replication Unhealthy | `dht_replication_health < 0.8` |
| Memory High | Per-node > 300 MB |

### Info Alerts (P3 - Informational)
| Alert | Condition |
|-------|-----------|
| Close Group Failures | `dht_security_close_group_consensus_failures_total` increases |
| Witness Failures | `dht_security_witness_failures_total` increases |
| Node Evictions | `dht_security_nodes_evicted_total` increases |

### Dashboard Panels (see grafana-saorsa-complete.json)
1. **Network Overview** - Total nodes, health status, system status
2. **Security Dashboard** - Attack scores, BFT mode, evictions
3. **Trust Metrics** - EigenTrust, witness validation, interactions
4. **DHT Performance** - Latency percentiles, hop counts, success rates
5. **Placement Metrics** - Geographic diversity, load balancing, capacity
6. **Payment Metrics** - Quotes generated, payments received
7. **Data Integrity** - Audits, integrity checks, corruption detection
8. **Resource Usage** - CPU, memory, bandwidth per node

---

## Test Schedule

| Day | Focus Area |
|-----|------------|
| Day 1 | Infrastructure validation (Phase 1) |
| Day 2 | Network formation + sibling broadcast (Phase 2) |
| Day 3 | Payment & data operations (Phase 3-4) |
| Day 4 | Security testing - Sybil, Eclipse, Collusion (Phase 5.1-5.4) |
| Day 5 | Security testing - Close Group, BFT, Trust (Phase 5.5-5.7) |
| Day 6 | Security testing - IP/Geo Diversity (Phase 5.8-5.9) |
| Day 7 | Security testing - Trust Enforcement, Close Group Analysis (Phase 5.10-5.11) |
| Day 8 | Performance benchmarks (Phase 6) |
| Day 9 | Chaos + adversarial testing (Phase 7) |

---

## Success Criteria

### Minimum Viable Testnet
- [ ] 500 nodes running for 24+ hours
- [ ] DHT operations succeed > 99%
- [ ] Payment quotes generated successfully
- [ ] No memory leaks (stable RSS over 24h)
- [ ] All security scores < 0.3 (no active attacks)
- [ ] Low trust nodes < 10% of network

### Production Readiness
- [ ] All Phase 1-7 tests pass (including new 5.8-5.12)
- [ ] Chaos engineering tests show recovery
- [ ] P95 latency < 500ms sustained
- [ ] Zero critical alerts for 48+ hours
- [ ] Security dashboard shows all healthy
- [ ] Trust metrics stable (EigenTrust avg > 0.7)
- [ ] Adversarial tests detected and recovered
- [ ] IP/Geographic diversity enforcement active
- [ ] Enforcement mode remains permissive (0) for 48+ hours
- [ ] Close group failure analysis shows no collusion patterns
- [ ] All 60+ metrics reporting correctly
