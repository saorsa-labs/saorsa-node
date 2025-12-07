# 500-Node Testnet Test Plan

## Version Information

- **saorsa-node**: v0.1.0
- **saorsa-core**: v0.7.3
- **Target**: 500 nodes across 5 Digital Ocean workers

## saorsa-core 0.7.3 Changes Summary

### New Features
- **routing_maintenance module**: Comprehensive routing table maintenance
  - `attestation.rs` - Data attestation using nonce-prepended hash challenges
  - `eviction.rs` - Ill-behaving node removal
  - `liveness.rs` - Node liveness tracking
  - `refresh.rs` - Periodic routing table refresh
  - `scheduler.rs` - Maintenance task scheduling
  - `validator.rs` - Node validity verification via close group consensus

### Bug Fixes
- Weighted shard distribution favoring headless devices
- Deadlock fix in storage API functions
- Thompson sampling test boundary case
- Windows time arithmetic overflow fixes
- Multiple test reliability improvements

---

## Phase 1: Infrastructure Validation

### 1.1 Bootstrap Node Health
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Bootstrap connectivity | Bootstrap nodes accessible | TCP/UDP 12000 responds |
| TLS handshake | PQC key exchange works | ML-KEM-768 completes |
| Health endpoint | /health returns OK | HTTP 200, all components healthy |
| Metrics endpoint | /metrics returns data | Prometheus format valid |

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
| Time to 500 nodes | < 10 minutes | All nodes report `p2p_health_status{component="dht"} 1` |
| Routing table size | 8-20 peers average | `p2p_dht_routing_table_size` |
| Geographic diversity | 3+ regions represented | Node distribution by IP geolocation |

### 2.2 Node Discovery (Routing Maintenance - NEW in 0.7.3)
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Bucket refresh | Periodic refresh works | `routing_refresh_operations_total` increases |
| Liveness checking | Dead nodes detected | `routing_liveness_failures_total` > 0 when nodes die |
| Eviction | Misbehaving nodes removed | `routing_evictions_total` correlates with bad behavior |
| Attestation | Data challenges succeed | `routing_attestation_success_rate` > 0.95 |

### 2.3 Connection Stability
| Metric | Target | Measurement |
|--------|--------|-------------|
| Active connections | 8-20 per node | `p2p_network_active_connections` |
| Connection success rate | > 95% | `p2p_connection_attempts_total` vs `p2p_connection_failures_total` |
| Keepalive success | > 99% | No unexpected disconnections |

---

## Phase 3: Payment System Tests

### 3.1 Quote Generation
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Quote creation | Node generates valid quotes | `PaymentQuote` returned |
| Quote signing | Quotes are cryptographically signed | Signature verifies |
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

### 4.2 DHT Telemetry (saorsa-core)
| Metric | Target |
|--------|--------|
| `p50_latency_ms` | < 100ms |
| `p95_latency_ms` | < 500ms |
| `p99_latency_ms` | < 1s |
| `success_rate` (GET) | > 99% |
| `success_rate` (PUT) | > 99% |
| `avg_hops` | < 6 |

### 4.3 Replication
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| K-value replication | Data on K nodes | Query any K/2 nodes returns data |
| Cross-region | Data survives region failure | Data retrievable after region dropout |
| Weighted distribution | Headless devices get more shards | Shards favor high-capacity nodes |

---

## Phase 5: Security Tests

### 5.1 Sybil Resistance
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Node age verification | New nodes restricted | Age < 1hr cannot replicate |
| Trust accumulation | Trust increases over time | Trust score correlates with age |
| Rate limiting | Excessive requests blocked | Connection refused after threshold |

### 5.2 Network Attacks
| Test | Description | Pass Criteria |
|------|-------------|---------------|
| Eclipse attack | Single node can't dominate routing | Max 20% from same /24 subnet |
| Partition resilience | Network recovers from split | DHT reforms within 5 minutes |
| Byzantine tolerance | Bad nodes don't corrupt data | Data integrity maintained |

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

---

## Monitoring & Alerting

### Critical Alerts (P1)
- `p2p_unhealthy_components > 0` for > 5 minutes
- `p2p_health_status{component="dht"} == 0`
- Node count drops below 400

### Warning Alerts (P2)
- `p95_latency_ms > 1000`
- `success_rate < 0.95`
- Memory usage > 300 MB per node

### Dashboard Panels (see grafana-dashboard.json)
1. Network Overview - total nodes, health status
2. DHT Performance - latency percentiles, hop counts
3. Storage Metrics - capacity, operations/sec
4. Payment Metrics - quotes generated, payments received
5. Resource Usage - CPU, memory, bandwidth per node
6. Error Analysis - error types, failure rates

---

## Test Schedule

| Day | Focus Area |
|-----|------------|
| Day 1 | Infrastructure validation (Phase 1) |
| Day 2 | Network formation (Phase 2) |
| Day 3 | Payment & data tests (Phase 3-4) |
| Day 4 | Security tests (Phase 5) |
| Day 5 | Performance benchmarks (Phase 6) |
| Day 6-7 | Chaos engineering (Phase 7) |

---

## Success Criteria

### Minimum Viable Testnet
- [ ] 500 nodes running for 24+ hours
- [ ] DHT operations succeed > 99%
- [ ] Payment quotes generated successfully
- [ ] No memory leaks (stable RSS over 24h)

### Production Readiness
- [ ] All Phase 1-6 tests pass
- [ ] Chaos engineering tests show recovery
- [ ] P95 latency < 500ms sustained
- [ ] Zero critical alerts for 48+ hours
