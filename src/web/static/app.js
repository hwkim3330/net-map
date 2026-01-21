/**
 * Net-Map - Network Packet Analyzer
 * Enhanced UI with Network Scanning & Analysis
 */

class NetMap {
    constructor() {
        this.packets = [];
        this.capturing = false;
        this.newestId = 0;
        this.pollInterval = null;
        this.statusInterval = null;
        this.startTime = null;

        // Connection state
        this.connected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.pollErrors = 0;
        this.maxPollErrors = 3;

        // Statistics
        this.totalBytes = 0;
        this.protocolCounts = {};
        this.sourceCounts = {};
        this.sizeBuckets = { '0-64': 0, '65-128': 0, '129-256': 0, '257-512': 0, '513-1024': 0, '1025+': 0 };

        // Hosts tracking
        this.hosts = new Map();

        // Topology data
        this.nodes = new Map();
        this.links = new Map();

        // Pagination
        this.pageSize = 100;
        this.currentPage = 1;
        this.autoScroll = true;

        // Rate calculation
        this.lastPacketCount = 0;
        this.lastByteCount = 0;
        this.lastRateTime = Date.now();

        // IO Graph data
        this.ioGraphData = [];
        this.ioGraphInterval = 500;

        // Performance optimization - batch updates
        this.pendingPackets = [];
        this.renderScheduled = false;
        this.lastChartUpdate = 0;
        this.chartUpdateInterval = 500; // Update charts every 500ms max
        this.lastTableRender = 0;
        this.tableRenderInterval = 100; // Render table every 100ms max

        // Packet navigation (like PacketSniffer)
        this.selectedPacketIndex = -1;
        this.currentZoom = 100;

        this.init();
    }

    init() {
        this.initElements();
        this.initCharts();
        this.initTopology();
        this.initIOGraph();
        this.initAdvancedCharts();
        this.initEventListeners();
        this.loadDevices();
        this.startRateCalculation();
        this.startStatusPolling();
    }

    initElements() {
        this.deviceSelect = document.getElementById('device-select');
        this.filterInput = document.getElementById('filter-input');
        this.startBtn = document.getElementById('start-btn');
        this.stopBtn = document.getElementById('stop-btn');
        this.clearBtn = document.getElementById('clear-btn');
        this.captureStatus = document.getElementById('capture-status');
        this.packetTbody = document.getElementById('packet-tbody');
        this.detailPlaceholder = document.getElementById('detail-placeholder');
        this.detailContent = document.getElementById('detail-content');

        // Stats elements
        this.statPackets = document.getElementById('stat-packets');
        this.statDisplayed = document.getElementById('stat-displayed');
        this.statBytes = document.getElementById('stat-bytes');
        this.statPps = document.getElementById('stat-pps');
        this.statBps = document.getElementById('stat-bps');
        this.statHosts = document.getElementById('stat-hosts');
        this.statDuration = document.getElementById('stat-duration');

        // Footer status
        this.connectionStatus = document.getElementById('connection-status');
        this.statusDot = document.getElementById('status-dot');

        // Hex dump
        this.hexPlaceholder = document.getElementById('hex-placeholder');
        this.hexContent = document.getElementById('hex-content');
        this.hexDump = document.getElementById('hex-dump');
    }

    initEventListeners() {
        this.startBtn?.addEventListener('click', () => this.startCapture());
        this.stopBtn?.addEventListener('click', () => this.stopCapture());
        this.clearBtn?.addEventListener('click', () => this.clearPackets());
        document.getElementById('restart-btn')?.addEventListener('click', () => this.restartCapture());

        // Filter buttons
        document.getElementById('apply-filter-btn')?.addEventListener('click', () => this.applyFilter());
        document.getElementById('clear-filter-btn')?.addEventListener('click', () => this.clearFilter());
        this.filterInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.applyFilter();
        });

        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchTab(e.target));
        });

        // Stats tab switching
        document.querySelectorAll('.stats-tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchStatsTab(e.target));
        });

        // Network scan - init all scan event listeners
        this.initScanEventListeners();

        // Topology
        document.getElementById('topology-reset')?.addEventListener('click', () => this.resetTopology());
        document.getElementById('topology-center')?.addEventListener('click', () => this.centerTopology());
        document.getElementById('topology-cluster')?.addEventListener('click', () => this.clusterTopology());
        document.getElementById('topology-labels')?.addEventListener('change', (e) => this.toggleLabels(e.target.checked));
        document.getElementById('topology-layout')?.addEventListener('change', (e) => this.changeLayout(e.target.value));
        document.getElementById('topology-animate')?.addEventListener('change', (e) => this.toggleAnimation(e.target.checked));
        document.getElementById('topology-search')?.addEventListener('input', (e) => this.searchTopology(e.target.value));
        document.getElementById('info-close')?.addEventListener('click', () => this.closeTopologyInfo());
        document.getElementById('info-filter')?.addEventListener('click', () => this.filterFromInfo());
        document.getElementById('info-highlight')?.addEventListener('click', () => this.highlightFromInfo());

        // IO Graph controls
        document.getElementById('iograph-interval')?.addEventListener('change', (e) => {
            this.ioGraphInterval = parseInt(e.target.value);
        });

        // Hex copy
        document.getElementById('hex-copy')?.addEventListener('click', () => this.copyHex());

        // Export buttons
        document.getElementById('export-pcap-btn')?.addEventListener('click', () => this.exportPcap());
        document.getElementById('export-csv-btn')?.addEventListener('click', () => this.exportCSV());

        // Load PCAP file
        document.getElementById('load-pcap-btn')?.addEventListener('click', () => {
            document.getElementById('pcap-file-input')?.click();
        });
        document.getElementById('pcap-file-input')?.addEventListener('change', (e) => this.loadPcapFile(e));

        // Replay packets
        document.getElementById('replay-btn')?.addEventListener('click', () => this.replayPackets());

        // Coloring rules
        document.getElementById('coloring-rules-btn')?.addEventListener('click', () => this.showColoringDialog());
        document.getElementById('coloring-close')?.addEventListener('click', () => this.hideColoringDialog());
        document.getElementById('coloring-apply')?.addEventListener('click', () => this.applyColoringRules());
        document.getElementById('coloring-reset')?.addEventListener('click', () => this.resetColoringRules());

        // Follow Stream dialog
        document.getElementById('stream-close')?.addEventListener('click', () => this.hideStreamDialog());
        document.getElementById('stream-copy')?.addEventListener('click', () => this.copyStreamContent());
        document.getElementById('stream-save')?.addEventListener('click', () => this.saveStreamContent());
        document.getElementById('stream-format')?.addEventListener('change', (e) => this.updateStreamFormat(e.target.value));

        // Context menu
        this.initContextMenu();

        // Zoom controls
        document.getElementById('zoom-in-btn')?.addEventListener('click', () => this.zoomIn());
        document.getElementById('zoom-out-btn')?.addEventListener('click', () => this.zoomOut());
        document.getElementById('fullscreen-btn')?.addEventListener('click', () => this.toggleFullscreen());

        // Keyboard shortcuts (like PacketSniffer)
        document.addEventListener('keydown', (e) => {
            // Ctrl+E: Toggle capture
            if (e.ctrlKey && e.key === 'e') {
                e.preventDefault();
                this.capturing ? this.stopCapture() : this.startCapture();
            }
            // Ctrl+S: Save PCAP
            if (e.ctrlKey && e.key === 's') {
                e.preventDefault();
                this.savePcap();
            }
            // F5: Start capture
            if (e.key === 'F5' && !e.ctrlKey) {
                e.preventDefault();
                if (!this.capturing) this.startCapture();
            }
            // F6: Stop capture
            if (e.key === 'F6') {
                e.preventDefault();
                if (this.capturing) this.stopCapture();
            }
            // F11: Fullscreen
            if (e.key === 'F11') {
                e.preventDefault();
                this.toggleFullscreen();
            }
            // Ctrl++: Zoom in
            if (e.ctrlKey && (e.key === '+' || e.key === '=')) {
                e.preventDefault();
                this.zoomIn();
            }
            // Ctrl+-: Zoom out
            if (e.ctrlKey && e.key === '-') {
                e.preventDefault();
                this.zoomOut();
            }
            // Ctrl+0: Reset zoom
            if (e.ctrlKey && e.key === '0') {
                e.preventDefault();
                this.resetZoom();
            }
            // Ctrl+Up: Previous packet
            if (e.ctrlKey && e.key === 'ArrowUp') {
                e.preventDefault();
                this.selectPreviousPacket();
            }
            // Ctrl+Down: Next packet
            if (e.ctrlKey && e.key === 'ArrowDown') {
                e.preventDefault();
                this.selectNextPacket();
            }
            // Home: First packet
            if (e.key === 'Home' && !e.ctrlKey) {
                e.preventDefault();
                this.goToFirstPacket();
            }
            // End: Last packet
            if (e.key === 'End' && !e.ctrlKey) {
                e.preventDefault();
                this.goToLastPacket();
            }
            // Ctrl+Delete: Clear all
            if (e.ctrlKey && e.key === 'Delete') {
                e.preventDefault();
                this.clearPackets();
            }
            // Ctrl+F: Focus filter
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                this.filterInput?.focus();
                this.filterInput?.select();
            }
            // Escape: Clear selection / close dialogs
            if (e.key === 'Escape') {
                this.hideStreamDialog?.();
                this.hideColoringDialog?.();
                document.getElementById('packet-context-menu')?.style.setProperty('display', 'none');
            }
        });

        // Auto-scroll checkbox
        document.getElementById('auto-scroll')?.addEventListener('change', (e) => {
            this.autoScroll = e.target.checked;
            if (this.autoScroll) {
                const totalPages = Math.ceil(this.packets.length / this.pageSize);
                this.currentPage = totalPages;
                this.renderPacketTable();
                this.updatePagination();
            }
        });

        // Auto-stop capture when browser closes
        window.addEventListener('beforeunload', () => {
            if (this.capturing) {
                navigator.sendBeacon('/api/capture/stop', '');
            }
        });

        // Duration timer
        this.durationInterval = setInterval(() => this.updateDuration(), 1000);
    }

    switchStatsTab(tabBtn) {
        const tabName = tabBtn.dataset.statstab;

        // Update tab buttons
        document.querySelectorAll('.stats-tab').forEach(t => t.classList.remove('active'));
        tabBtn.classList.add('active');

        // Update tab content
        document.querySelectorAll('.stats-content').forEach(c => c.classList.remove('active'));
        document.getElementById(`stats-${tabName}`)?.classList.add('active');

        // Refresh specific content
        if (tabName === 'protocol') {
            this.updateProtocolHierarchy();
        } else if (tabName === 'conversations') {
            this.updateConversations();
        } else if (tabName === 'endpoints') {
            this.updateEndpoints();
        } else if (tabName === 'ports') {
            this.updatePorts();
        } else if (tabName === 'iograph') {
            this.ioGraphChart?.resize();
            this.rebuildIOGraph();
        }
    }

    updateProtocolHierarchy() {
        const tbody = document.getElementById('protocol-tbody');
        if (!tbody) return;

        const total = this.packets.length || 1;
        const protocols = Object.entries(this.protocolCounts)
            .sort((a, b) => b[1] - a[1]);

        tbody.innerHTML = '';
        protocols.forEach(([proto, count]) => {
            const percent = ((count / total) * 100).toFixed(1);
            const protoPackets = this.packets.filter(p => p.protocol === proto);
            const bytes = protoPackets.reduce((sum, p) => sum + p.length, 0);
            const avgSize = count > 0 ? Math.round(bytes / count) : 0;

            const row = document.createElement('tr');
            row.dataset.protocol = proto;
            row.innerHTML = `
                <td><span class="proto-indicator proto-${proto.toLowerCase()}"></span>${proto}</td>
                <td>${percent}%</td>
                <td>${count.toLocaleString()}</td>
                <td>${this.formatBytes(bytes)}</td>
                <td>${avgSize} B</td>
            `;
            row.addEventListener('click', () => this.filterByProtocol(proto));
            tbody.appendChild(row);
        });
    }

    filterByProtocol(proto) {
        if (this.filterInput) {
            this.filterInput.value = proto.toLowerCase();
        }
        this.filteredPackets = this.packets.filter(pkt =>
            pkt.protocol?.toLowerCase() === proto.toLowerCase()
        );
        this.currentPage = 1;
        this.renderFilteredTable();

        // Highlight selected row
        document.querySelectorAll('#protocol-tbody tr').forEach(r => r.classList.remove('selected'));
        document.querySelector(`#protocol-tbody tr[data-protocol="${proto}"]`)?.classList.add('selected');

        const infoEl = document.getElementById('selected-packet-info');
        if (infoEl) {
            infoEl.textContent = `Protocol: ${proto} (${this.filteredPackets.length} packets)`;
        }
    }

    updateConversations() {
        const tbody = document.getElementById('conv-tbody');
        if (!tbody) return;

        // Build conversation map with port info
        const conversations = new Map();
        this.packets.forEach(pkt => {
            if (!pkt.src || !pkt.dst) return;

            const srcPort = pkt.tcp?.src_port || pkt.udp?.src_port || 0;
            const dstPort = pkt.tcp?.dst_port || pkt.udp?.dst_port || 0;

            // Create unique key including ports
            const addrA = pkt.src < pkt.dst ? pkt.src : pkt.dst;
            const addrB = pkt.src < pkt.dst ? pkt.dst : pkt.src;
            const portA = pkt.src < pkt.dst ? srcPort : dstPort;
            const portB = pkt.src < pkt.dst ? dstPort : srcPort;
            const key = `${addrA}:${portA}-${addrB}:${portB}`;

            if (!conversations.has(key)) {
                conversations.set(key, {
                    addrA, addrB, portA, portB,
                    packets: 0,
                    bytes: 0,
                    firstSeen: pkt.timestamp,
                    lastSeen: pkt.timestamp
                });
            }
            const conv = conversations.get(key);
            conv.packets++;
            conv.bytes += pkt.length;
            conv.lastSeen = pkt.timestamp;
        });

        tbody.innerHTML = '';
        Array.from(conversations.values())
            .sort((a, b) => b.packets - a.packets)
            .slice(0, 100)
            .forEach(conv => {
                const duration = ((conv.lastSeen - conv.firstSeen) / 1000000).toFixed(2);
                const row = document.createElement('tr');
                row.dataset.addra = conv.addrA;
                row.dataset.addrb = conv.addrB;
                row.innerHTML = `
                    <td>${conv.addrA}</td>
                    <td>${conv.portA || '-'}</td>
                    <td>${conv.addrB}</td>
                    <td>${conv.portB || '-'}</td>
                    <td>${conv.packets.toLocaleString()}</td>
                    <td>${this.formatBytes(conv.bytes)}</td>
                    <td>${duration}s</td>
                `;
                row.addEventListener('click', () => this.filterByConversation(conv.addrA, conv.addrB));
                tbody.appendChild(row);
            });
    }

    filterByConversation(addrA, addrB) {
        if (this.filterInput) {
            this.filterInput.value = `(ip.addr == ${addrA}) && (ip.addr == ${addrB})`;
        }
        this.filteredPackets = this.packets.filter(pkt =>
            (pkt.src === addrA && pkt.dst === addrB) ||
            (pkt.src === addrB && pkt.dst === addrA)
        );
        this.currentPage = 1;
        this.renderFilteredTable();

        const infoEl = document.getElementById('selected-packet-info');
        if (infoEl) {
            infoEl.textContent = `Conversation: ${addrA} ↔ ${addrB} (${this.filteredPackets.length} packets)`;
        }
    }

    updateEndpoints() {
        const tbody = document.getElementById('endpoint-tbody');
        if (!tbody) return;

        // Calculate Tx/Rx for each host
        const endpointStats = new Map();
        this.packets.forEach(pkt => {
            if (pkt.src) {
                if (!endpointStats.has(pkt.src)) {
                    endpointStats.set(pkt.src, { ip: pkt.src, txPkts: 0, rxPkts: 0, txBytes: 0, rxBytes: 0 });
                }
                const stats = endpointStats.get(pkt.src);
                stats.txPkts++;
                stats.txBytes += pkt.length;
            }
            if (pkt.dst) {
                if (!endpointStats.has(pkt.dst)) {
                    endpointStats.set(pkt.dst, { ip: pkt.dst, txPkts: 0, rxPkts: 0, txBytes: 0, rxBytes: 0 });
                }
                const stats = endpointStats.get(pkt.dst);
                stats.rxPkts++;
                stats.rxBytes += pkt.length;
            }
        });

        tbody.innerHTML = '';
        Array.from(endpointStats.values())
            .sort((a, b) => (b.txPkts + b.rxPkts) - (a.txPkts + a.rxPkts))
            .slice(0, 100)
            .forEach(ep => {
                const totalPkts = ep.txPkts + ep.rxPkts;
                const totalBytes = ep.txBytes + ep.rxBytes;
                const row = document.createElement('tr');
                row.dataset.ip = ep.ip;
                row.innerHTML = `
                    <td>${ep.ip}</td>
                    <td>${totalPkts.toLocaleString()}</td>
                    <td>${this.formatBytes(totalBytes)}</td>
                    <td>${ep.txPkts.toLocaleString()}</td>
                    <td>${ep.rxPkts.toLocaleString()}</td>
                    <td>${this.formatBytes(ep.txBytes)}</td>
                    <td>${this.formatBytes(ep.rxBytes)}</td>
                `;
                row.addEventListener('click', () => this.filterByHost(ep.ip));
                tbody.appendChild(row);
            });
    }

    updatePorts() {
        const tbody = document.getElementById('ports-tbody');
        if (!tbody) return;

        // Well-known port services
        const services = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
            123: 'NTP', 143: 'IMAP', 161: 'SNMP', 443: 'HTTPS', 445: 'SMB',
            465: 'SMTPS', 514: 'Syslog', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 27017: 'MongoDB'
        };

        // Collect port statistics
        const portStats = new Map();
        const connections = new Map();

        this.packets.forEach(pkt => {
            const srcPort = pkt.tcp?.src_port || pkt.udp?.src_port;
            const dstPort = pkt.tcp?.dst_port || pkt.udp?.dst_port;
            const proto = pkt.tcp ? 'TCP' : (pkt.udp ? 'UDP' : null);

            if (!proto) return;

            [srcPort, dstPort].forEach(port => {
                if (!port) return;
                const key = `${port}-${proto}`;
                if (!portStats.has(key)) {
                    portStats.set(key, {
                        port, proto,
                        service: services[port] || '',
                        packets: 0,
                        bytes: 0,
                        connections: new Set()
                    });
                }
                const stats = portStats.get(key);
                stats.packets++;
                stats.bytes += pkt.length;

                // Track unique connections
                if (pkt.src && pkt.dst) {
                    stats.connections.add(`${pkt.src}-${pkt.dst}`);
                }
            });
        });

        tbody.innerHTML = '';
        Array.from(portStats.values())
            .sort((a, b) => b.packets - a.packets)
            .slice(0, 100)
            .forEach(ps => {
                const row = document.createElement('tr');
                row.dataset.port = ps.port;
                row.dataset.proto = ps.proto;
                row.innerHTML = `
                    <td><strong>${ps.port}</strong></td>
                    <td>${ps.service || '-'}</td>
                    <td>${ps.proto}</td>
                    <td>${ps.packets.toLocaleString()}</td>
                    <td>${this.formatBytes(ps.bytes)}</td>
                    <td>${ps.connections.size}</td>
                `;
                row.addEventListener('click', () => this.filterByPort(ps.port, ps.proto));
                tbody.appendChild(row);
            });
    }

    filterByPort(port, proto) {
        const protoLower = proto.toLowerCase();
        if (this.filterInput) {
            this.filterInput.value = `${protoLower}.port == ${port}`;
        }
        this.filteredPackets = this.packets.filter(pkt => {
            if (protoLower === 'tcp' && pkt.tcp) {
                return pkt.tcp.src_port === port || pkt.tcp.dst_port === port;
            }
            if (protoLower === 'udp' && pkt.udp) {
                return pkt.udp.src_port === port || pkt.udp.dst_port === port;
            }
            return false;
        });
        this.currentPage = 1;
        this.renderFilteredTable();

        const infoEl = document.getElementById('selected-packet-info');
        if (infoEl) {
            infoEl.textContent = `Port: ${port}/${proto} (${this.filteredPackets.length} packets)`;
        }
    }

    updateDuration() {
        if (!this.statDuration) return;

        if (this.capturing && this.startTime) {
            const elapsed = Math.floor((Date.now() - this.startTime) / 1000);
            const hours = Math.floor(elapsed / 3600);
            const mins = Math.floor((elapsed % 3600) / 60);
            const secs = elapsed % 60;
            this.statDuration.textContent =
                `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
        } else if (!this.capturing) {
            // Keep last duration or reset
        }
    }

    restartCapture() {
        if (this.capturing) {
            this.stopCapture();
        }
        this.clearPackets();
        setTimeout(() => this.startCapture(), 500);
    }

    showHexDump(pkt) {
        if (!this.hexPlaceholder || !this.hexContent || !this.hexDump) return;

        this.hexPlaceholder.style.display = 'none';
        this.hexContent.style.display = 'block';

        let bytes;

        if (pkt.raw_data) {
            // Decode base64 raw data if available
            try {
                const binary = atob(pkt.raw_data);
                bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) {
                    bytes[i] = binary.charCodeAt(i);
                }
            } catch (e) {
                this.hexDump.textContent = 'Error decoding packet data';
                return;
            }
        } else {
            // Generate pseudo hex dump from packet headers
            bytes = this.generatePseudoHexDump(pkt);
        }

        // Generate hex dump display
        let html = '';
        const bytesPerLine = 16;

        for (let offset = 0; offset < bytes.length; offset += bytesPerLine) {
            const lineBytes = bytes.slice(offset, offset + bytesPerLine);

            // Offset
            const offsetStr = offset.toString(16).padStart(8, '0');

            // Hex bytes
            let hexStr = '';
            for (let i = 0; i < bytesPerLine; i++) {
                if (i < lineBytes.length) {
                    hexStr += lineBytes[i].toString(16).padStart(2, '0') + ' ';
                } else {
                    hexStr += '   ';
                }
                if (i === 7) hexStr += ' ';
            }

            // ASCII
            let asciiStr = '';
            for (let i = 0; i < lineBytes.length; i++) {
                const b = lineBytes[i];
                asciiStr += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
            }

            html += `<div class="hex-line">`;
            html += `<span class="hex-offset">${offsetStr}</span>`;
            html += `<span class="hex-bytes">${hexStr}</span>`;
            html += `<span class="hex-ascii">${asciiStr}</span>`;
            html += `</div>`;
        }

        this.hexDump.innerHTML = html;
    }

    // Generate pseudo hex dump from packet header info
    generatePseudoHexDump(pkt) {
        const bytes = [];

        // Ethernet header (14 bytes)
        if (pkt.ethernet) {
            // Destination MAC
            const dstMac = pkt.ethernet.dst_mac?.split(':').map(x => parseInt(x, 16)) || [0,0,0,0,0,0];
            bytes.push(...dstMac);
            // Source MAC
            const srcMac = pkt.ethernet.src_mac?.split(':').map(x => parseInt(x, 16)) || [0,0,0,0,0,0];
            bytes.push(...srcMac);
            // EtherType
            const ethertype = pkt.ethernet.ethertype || 0x0800;
            bytes.push((ethertype >> 8) & 0xff, ethertype & 0xff);
        }

        // IP header (20 bytes minimum)
        if (pkt.ip) {
            const ip = pkt.ip;
            // Version + IHL
            bytes.push((ip.version << 4) | (ip.ihl || 5));
            // TOS
            bytes.push(ip.tos || 0);
            // Total Length
            bytes.push((ip.total_len >> 8) & 0xff, ip.total_len & 0xff);
            // ID
            bytes.push((ip.id >> 8) & 0xff, ip.id & 0xff);
            // Flags + Fragment Offset
            const flagsOff = ((ip.flags || 0) << 13) | (ip.frag_offset || 0);
            bytes.push((flagsOff >> 8) & 0xff, flagsOff & 0xff);
            // TTL
            bytes.push(ip.ttl || 64);
            // Protocol
            bytes.push(ip.protocol || 0);
            // Checksum
            bytes.push((ip.checksum >> 8) & 0xff, ip.checksum & 0xff);
            // Source IP
            const srcParts = ip.src?.split('.').map(Number) || [0,0,0,0];
            bytes.push(...srcParts);
            // Destination IP
            const dstParts = ip.dst?.split('.').map(Number) || [0,0,0,0];
            bytes.push(...dstParts);
        }

        // TCP header (20 bytes minimum)
        if (pkt.tcp) {
            const tcp = pkt.tcp;
            // Source Port
            bytes.push((tcp.src_port >> 8) & 0xff, tcp.src_port & 0xff);
            // Destination Port
            bytes.push((tcp.dst_port >> 8) & 0xff, tcp.dst_port & 0xff);
            // Sequence Number
            bytes.push((tcp.seq >> 24) & 0xff, (tcp.seq >> 16) & 0xff, (tcp.seq >> 8) & 0xff, tcp.seq & 0xff);
            // Acknowledgment Number
            bytes.push((tcp.ack >> 24) & 0xff, (tcp.ack >> 16) & 0xff, (tcp.ack >> 8) & 0xff, tcp.ack & 0xff);
            // Data Offset + Flags
            bytes.push(((tcp.data_offset || 5) << 4), tcp.flags || 0);
            // Window
            bytes.push((tcp.window >> 8) & 0xff, tcp.window & 0xff);
            // Checksum
            bytes.push((tcp.checksum >> 8) & 0xff, tcp.checksum & 0xff);
            // Urgent Pointer
            bytes.push((tcp.urgent >> 8) & 0xff, tcp.urgent & 0xff);
        }

        // UDP header (8 bytes)
        if (pkt.udp) {
            const udp = pkt.udp;
            // Source Port
            bytes.push((udp.src_port >> 8) & 0xff, udp.src_port & 0xff);
            // Destination Port
            bytes.push((udp.dst_port >> 8) & 0xff, udp.dst_port & 0xff);
            // Length
            bytes.push((udp.length >> 8) & 0xff, udp.length & 0xff);
            // Checksum
            bytes.push((udp.checksum >> 8) & 0xff, udp.checksum & 0xff);
        }

        // Pad with zeros to match packet length (approximation)
        const headerLen = bytes.length;
        const payloadLen = Math.min(pkt.length - headerLen, 64); // Show up to 64 bytes of payload placeholder
        for (let i = 0; i < payloadLen; i++) {
            bytes.push(0x00);
        }

        return new Uint8Array(bytes);
    }

    copyHex() {
        if (!this.selectedPacket || !this.selectedPacket.raw_data) {
            alert('No packet selected');
            return;
        }

        try {
            const binary = atob(this.selectedPacket.raw_data);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }

            // Generate hex string
            let hexStr = '';
            for (let i = 0; i < bytes.length; i++) {
                hexStr += bytes[i].toString(16).padStart(2, '0');
                if ((i + 1) % 16 === 0) hexStr += '\n';
                else if ((i + 1) % 8 === 0) hexStr += '  ';
                else hexStr += ' ';
            }

            navigator.clipboard.writeText(hexStr.trim()).then(() => {
                // Visual feedback
                const btn = document.getElementById('hex-copy');
                if (btn) {
                    const original = btn.textContent;
                    btn.textContent = 'Copied!';
                    setTimeout(() => { btn.textContent = original; }, 1000);
                }
            });
        } catch (e) {
            alert('Failed to copy: ' + e.message);
        }
    }

    switchTab(tabBtn) {
        const tabGroup = tabBtn.closest('.tabs');
        const panel = tabBtn.closest('.panel');
        const tabName = tabBtn.dataset.tab;

        // Update tab buttons
        tabGroup.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tabBtn.classList.add('active');

        // Update tab content
        panel.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        panel.querySelector(`#tab-${tabName}`)?.classList.add('active');

        // Resize charts when dashboard becomes visible
        if (tabName === 'dashboard') {
            setTimeout(() => {
                this.trafficChart?.resize();
                this.protocolChart?.resize();
                this.sourcesChart?.resize();
                this.sizeChart?.resize();
            }, 100);
        }

        // Resize topology when visible
        if (tabName === 'topology') {
            setTimeout(() => this.resizeTopology(), 100);
        }

        // Update stats tabs content when switching
        if (tabName === 'protocol') {
            this.updateProtocolHierarchy();
            setTimeout(() => {
                this.protocolPieChart?.resize();
                this.updateCharts();
            }, 100);
        } else if (tabName === 'conversations') {
            this.updateConversations();
        } else if (tabName === 'endpoints') {
            this.updateEndpoints();
            setTimeout(() => {
                this.endpointsBarChart?.resize();
                this.updateEndpointsChart();
            }, 100);
        } else if (tabName === 'ports') {
            this.updatePorts();
            setTimeout(() => {
                this.portsBarChart?.resize();
                this.updatePortsChart();
            }, 100);
        } else if (tabName === 'iograph') {
            setTimeout(() => {
                this.ioGraphChart?.resize();
                this.rebuildIOGraph();
            }, 100);
        }
    }

    async loadDevices() {
        try {
            const response = await fetch('/api/devices');
            if (!response.ok) throw new Error('Server error');
            const data = await response.json();

            this.deviceSelect.innerHTML = '<option value="">Select Interface...</option>';
            if (data.devices && Array.isArray(data.devices)) {
                data.devices.forEach(device => {
                    const option = document.createElement('option');
                    option.value = device.name;
                    const displayName = device.ip ? `${device.description} (${device.ip})` : device.description;
                    option.textContent = displayName;
                    this.deviceSelect.appendChild(option);
                });
            }

            this.setConnected(true);
            this.reconnectAttempts = 0;
        } catch (error) {
            console.error('Failed to load devices:', error);
            this.setConnected(false);
            this.scheduleReconnect();
        }
    }

    setConnected(connected) {
        this.connected = connected;
        this.connectionStatus.textContent = connected ? 'Connected' : 'Disconnected';
        this.statusDot.classList.toggle('connected', connected);
        this.statusDot.classList.toggle('disconnected', !connected);
    }

    scheduleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 10000);
            console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
            setTimeout(() => this.loadDevices(), delay);
        }
    }

    // Poll server status periodically to sync state
    startStatusPolling() {
        this.statusInterval = setInterval(() => this.pollStatus(), 2000);
        this.pollStatus(); // Initial poll
    }

    async pollStatus() {
        try {
            const response = await fetch('/api/stats');
            if (!response.ok) throw new Error('Server error');
            const data = await response.json();

            this.setConnected(true);
            this.reconnectAttempts = 0;

            // Sync capture state with server
            const serverCapturing = data.capturing === true;
            if (serverCapturing !== this.capturing) {
                console.log(`Sync: server capturing=${serverCapturing}, client=${this.capturing}`);
                this.capturing = serverCapturing;
                this.updateCaptureUI();

                if (serverCapturing && !this.pollInterval) {
                    this.startPolling();
                } else if (!serverCapturing && this.pollInterval) {
                    this.stopPolling();
                }
            }

            // Update server-side stats
            if (data.buffer_count !== undefined) {
                // Server has packets we might not have fetched yet
            }
        } catch (error) {
            console.error('Status poll failed:', error);
            this.setConnected(false);
        }
    }

    async startCapture() {
        const device = this.deviceSelect.value;
        if (!device) {
            alert('Please select a network interface');
            return;
        }

        // Disable button during request
        this.startBtn.disabled = true;

        try {
            const response = await fetch('/api/capture/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    device: device,
                    filter: this.filterInput.value
                })
            });

            if (!response.ok) {
                const err = await response.json().catch(() => ({}));
                throw new Error(err.error || `HTTP ${response.status}`);
            }

            const data = await response.json();
            if (data.success) {
                this.capturing = true;
                this.startTime = Date.now();
                this.pollErrors = 0;
                this.updateCaptureUI();
                this.startPolling();
            } else {
                throw new Error(data.error || 'Unknown error');
            }
        } catch (error) {
            console.error('Failed to start capture:', error);
            alert('Failed to start capture: ' + error.message);
            this.startBtn.disabled = false;
        }
    }

    async stopCapture() {
        // Disable button during request
        this.stopBtn.disabled = true;

        try {
            const response = await fetch('/api/capture/stop', { method: 'POST' });
            if (!response.ok) {
                console.warn('Stop request returned:', response.status);
            }
        } catch (error) {
            console.error('Failed to stop capture:', error);
        } finally {
            // Always update UI, even if request failed
            this.capturing = false;
            this.updateCaptureUI();
            this.stopPolling();
        }
    }

    updateCaptureUI() {
        this.startBtn.disabled = this.capturing;
        this.stopBtn.disabled = !this.capturing;
        this.deviceSelect.disabled = this.capturing;

        this.captureStatus.textContent = this.capturing ? 'Capturing' : 'Stopped';
        this.captureStatus.className = 'capture-status ' + (this.capturing ? 'capturing' : 'stopped');

        // Update footer capture state indicator
        this.updateCaptureState(this.capturing ? 'Running' : 'Stopped');
    }

    startPolling() {
        if (this.pollInterval) return; // Already polling
        this.pollErrors = 0;

        // Network polling - fetch new packets from server
        this.pollInterval = setInterval(() => this.pollPackets(), 100);
        this.pollPackets(); // Immediate first poll

        // UI update timer - process buffered packets and update display (like PacketSniffer's CaptureTimer)
        this.uiUpdateInterval = setInterval(() => this.processPacketBuffer(), 50);
    }

    stopPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        if (this.uiUpdateInterval) {
            clearInterval(this.uiUpdateInterval);
            this.uiUpdateInterval = null;
        }
        // Process any remaining packets in buffer
        this.processPacketBuffer();
    }

    // Process pending packets from buffer (like PacketSniffer's CaptureTimer_Tick)
    processPacketBuffer() {
        if (this.pendingPackets.length === 0) return;

        // Move packets from buffer (atomic-like operation)
        const packetsToProcess = this.pendingPackets.splice(0, this.pendingPackets.length);

        // Process each packet (data only, no rendering)
        packetsToProcess.forEach(pkt => this.addPacketData(pkt));

        // Schedule single UI update for all processed packets
        this.scheduleRender();
    }

    async pollPackets() {
        if (!this.capturing) return;

        try {
            // Request all new packets since newestId (no limit - get whatever arrived)
            const fromId = this.newestId > 0 ? this.newestId + 1 : 0;
            const response = await fetch(`/api/packets?from=${fromId}`);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();
            this.pollErrors = 0; // Reset on success

            if (data.packets && Array.isArray(data.packets) && data.packets.length > 0) {
                // Filter duplicates and add to buffer (like PacketSniffer pattern)
                const newPackets = data.packets.filter(pkt => pkt.id > this.newestId);

                if (newPackets.length > 0) {
                    // Add to pending buffer (will be processed by UI timer)
                    this.pendingPackets.push(...newPackets);

                    // Update newestId to highest received
                    const lastPkt = newPackets[newPackets.length - 1];
                    this.newestId = lastPkt.id;
                }
            }
        } catch (error) {
            console.error('Failed to poll packets:', error);
            this.pollErrors++;

            if (this.pollErrors >= this.maxPollErrors) {
                console.warn('Too many poll errors, stopping capture');
                this.setConnected(false);
                this.stopPolling();
            }
        }
    }

    // Add packet data without rendering (for batch processing)
    addPacketData(pkt) {
        // Set startTime from first packet timestamp
        if (!this.startTime && pkt.timestamp) {
            this.startTime = pkt.timestamp;
        }

        this.packets.push(pkt);
        this.totalBytes += pkt.length;

        // Track protocol
        const proto = pkt.protocol || 'Unknown';
        this.protocolCounts[proto] = (this.protocolCounts[proto] || 0) + 1;

        // Track source/destination
        if (pkt.src) {
            this.sourceCounts[pkt.src] = (this.sourceCounts[pkt.src] || 0) + 1;
            this.trackHost(pkt.src, pkt);
        }
        if (pkt.dst) {
            this.trackHost(pkt.dst, pkt);
        }

        // Track size bucket
        const size = pkt.length;
        if (size <= 64) this.sizeBuckets['0-64']++;
        else if (size <= 128) this.sizeBuckets['65-128']++;
        else if (size <= 256) this.sizeBuckets['129-256']++;
        else if (size <= 512) this.sizeBuckets['257-512']++;
        else if (size <= 1024) this.sizeBuckets['513-1024']++;
        else this.sizeBuckets['1025+']++;

        // Update topology data (lightweight)
        this.updateTopologyData(pkt);

        // Update IO Graph data
        this.updateIOGraphData(pkt);
    }

    // Schedule a batched render using requestAnimationFrame
    scheduleRender() {
        if (this.renderScheduled) return;
        this.renderScheduled = true;

        requestAnimationFrame(() => {
            this.renderScheduled = false;
            this.batchedRender();
        });
    }

    // Perform batched UI updates
    batchedRender() {
        const now = Date.now();

        // Update table (throttled)
        if (now - this.lastTableRender >= this.tableRenderInterval) {
            this.lastTableRender = now;
            const totalPages = Math.ceil(this.packets.length / this.pageSize);
            if (this.autoScroll || this.currentPage === totalPages - 1) {
                this.currentPage = totalPages;
            }
            this.renderPacketTable();
            this.updatePagination();
        }

        // Update stats (always - lightweight)
        this.updateStats();

        // Update charts (throttled - expensive)
        if (now - this.lastChartUpdate >= this.chartUpdateInterval) {
            this.lastChartUpdate = now;
            this.updateCharts();
        }
    }

    addPacket(pkt) {
        // Use the optimized data-only add and schedule render
        this.addPacketData(pkt);
        this.scheduleRender();
    }

    trackHost(ip, pkt) {
        if (!ip || ip === '0.0.0.0' || ip.startsWith('255.')) return;

        if (!this.hosts.has(ip)) {
            this.hosts.set(ip, {
                ip: ip,
                mac: null,
                packets: 0,
                bytes: 0,
                firstSeen: pkt.timestamp,
                lastSeen: pkt.timestamp,
                protocols: new Set()
            });
        }

        const host = this.hosts.get(ip);
        host.packets++;
        host.bytes += pkt.length;
        host.lastSeen = pkt.timestamp;
        if (pkt.protocol) host.protocols.add(pkt.protocol);

        // Extract MAC from ethernet layer
        if (pkt.ethernet) {
            if (pkt.src === ip && pkt.ethernet.src_mac) {
                host.mac = pkt.ethernet.src_mac;
            } else if (pkt.dst === ip && pkt.ethernet.dst_mac) {
                host.mac = pkt.ethernet.dst_mac;
            }
        }
    }

    renderPacketTable() {
        const start = (this.currentPage - 1) * this.pageSize;
        const end = start + this.pageSize;
        const pagePackets = this.packets.slice(start, end);

        // Use DocumentFragment for better performance
        const fragment = document.createDocumentFragment();

        pagePackets.forEach(pkt => {
            const proto = pkt.protocol || 'Unknown';
            const row = document.createElement('tr');
            const colorClass = this.getPacketColorClass(pkt);
            row.className = `proto-${proto.toLowerCase()} ${colorClass}`;
            row.dataset.id = pkt.id;

            const time = this.formatTime(pkt.timestamp);

            row.innerHTML = `
                <td>${pkt.id}</td>
                <td>${time}</td>
                <td>${pkt.src || '-'}</td>
                <td>${pkt.dst || '-'}</td>
                <td>${proto}</td>
                <td>${pkt.length}</td>
                <td>${pkt.info || ''}</td>
            `;

            row.addEventListener('click', () => this.selectPacket(pkt, row));
            fragment.appendChild(row);
        });

        // Single DOM update
        this.packetTbody.innerHTML = '';
        this.packetTbody.appendChild(fragment);
    }

    updatePagination() {
        const totalPages = Math.ceil(this.packets.length / this.pageSize) || 1;
        const paginationEl = document.getElementById('pagination-info');
        if (paginationEl) {
            paginationEl.textContent = `Page ${this.currentPage} / ${totalPages} (${this.packets.length} packets)`;
        }
    }

    goToPage(page) {
        const totalPages = Math.ceil(this.packets.length / this.pageSize) || 1;
        if (page < 1) page = 1;
        if (page > totalPages) page = totalPages;
        this.currentPage = page;
        this.autoScroll = (page === totalPages);
        this.renderPacketTable();
        this.updatePagination();
    }

    prevPage() { this.goToPage(this.currentPage - 1); }
    nextPage() { this.goToPage(this.currentPage + 1); }
    firstPage() { this.goToPage(1); }
    lastPage() { this.goToPage(Math.ceil(this.packets.length / this.pageSize) || 1); }

    applyFilter() {
        const filter = this.filterInput?.value?.trim();
        if (!filter) {
            this.filteredPackets = null;
            this.currentPage = 1;
            this.renderPacketTable();
            this.updatePagination();
            const infoEl = document.getElementById('selected-packet-info');
            if (infoEl) infoEl.textContent = `Showing all ${this.packets.length} packets`;
            return;
        }

        const filterLower = filter.toLowerCase();

        // Parse complex filters with && and ||
        this.filteredPackets = this.packets.filter(pkt => {
            return this.evaluateFilter(pkt, filter, filterLower);
        });

        this.currentPage = 1;
        this.renderFilteredTable();
        this.updatePagination();
        this.updateStats();

        const infoEl = document.getElementById('selected-packet-info');
        if (infoEl) {
            infoEl.textContent = `Filter: ${filter} (${this.filteredPackets.length} packets)`;
        }
    }

    evaluateFilter(pkt, filter, filterLower) {
        // Handle && (AND) operator
        if (filter.includes('&&')) {
            const parts = filter.split('&&').map(s => s.trim());
            return parts.every(part => this.evaluateFilter(pkt, part, part.toLowerCase()));
        }

        // Handle || (OR) operator
        if (filter.includes('||')) {
            const parts = filter.split('||').map(s => s.trim());
            return parts.some(part => this.evaluateFilter(pkt, part, part.toLowerCase()));
        }

        // Remove parentheses for simple expressions
        let expr = filter.replace(/^\(|\)$/g, '').trim();
        let exprLower = expr.toLowerCase();

        // Handle != (not equal)
        if (expr.includes('!=')) {
            const [field, value] = expr.split('!=').map(s => s.trim());
            return !this.matchField(pkt, field.toLowerCase(), value);
        }

        // Handle == (equal)
        if (expr.includes('==')) {
            const [field, value] = expr.split('==').map(s => s.trim());
            return this.matchField(pkt, field.toLowerCase(), value);
        }

        // Handle contains
        if (exprLower.includes(' contains ')) {
            const [field, value] = expr.split(/\s+contains\s+/i).map(s => s.trim());
            return this.matchFieldContains(pkt, field.toLowerCase(), value);
        }

        // Simple protocol match
        if (['tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'https', 'tls', 'ipv4', 'ipv6'].includes(exprLower)) {
            if (exprLower === 'ipv4') return pkt.ip?.version === 4;
            if (exprLower === 'ipv6') return pkt.ip?.version === 6;
            if (exprLower === 'https' || exprLower === 'tls') {
                return (pkt.tcp?.dst_port === 443 || pkt.tcp?.src_port === 443);
            }
            return pkt.protocol?.toLowerCase() === exprLower;
        }

        // Text search in info or IP
        if (pkt.info?.toLowerCase().includes(exprLower)) return true;
        if (pkt.src?.includes(exprLower) || pkt.dst?.includes(exprLower)) return true;

        return false;
    }

    matchField(pkt, field, value) {
        const val = value.replace(/['"]/g, ''); // Remove quotes

        switch (field) {
            case 'ip.src':
                return pkt.src === val || pkt.src?.includes(val);
            case 'ip.dst':
                return pkt.dst === val || pkt.dst?.includes(val);
            case 'ip.addr':
                return pkt.src === val || pkt.dst === val || pkt.src?.includes(val) || pkt.dst?.includes(val);
            case 'tcp.port':
                const tcpPort = parseInt(val);
                return pkt.tcp?.src_port === tcpPort || pkt.tcp?.dst_port === tcpPort;
            case 'tcp.srcport':
            case 'tcp.src_port':
                return pkt.tcp?.src_port === parseInt(val);
            case 'tcp.dstport':
            case 'tcp.dst_port':
                return pkt.tcp?.dst_port === parseInt(val);
            case 'udp.port':
                const udpPort = parseInt(val);
                return pkt.udp?.src_port === udpPort || pkt.udp?.dst_port === udpPort;
            case 'udp.srcport':
            case 'udp.src_port':
                return pkt.udp?.src_port === parseInt(val);
            case 'udp.dstport':
            case 'udp.dst_port':
                return pkt.udp?.dst_port === parseInt(val);
            case 'eth.src':
            case 'eth.src_mac':
                return pkt.ethernet?.src_mac?.toLowerCase() === val.toLowerCase();
            case 'eth.dst':
            case 'eth.dst_mac':
                return pkt.ethernet?.dst_mac?.toLowerCase() === val.toLowerCase();
            case 'frame.len':
            case 'frame.length':
                return pkt.length === parseInt(val);
            case 'ip.ttl':
                return pkt.ip?.ttl === parseInt(val);
            case 'tcp.flags.syn':
                return pkt.tcp?.syn === (val === '1' || val.toLowerCase() === 'true');
            case 'tcp.flags.ack':
                return pkt.tcp?.ack_flag === (val === '1' || val.toLowerCase() === 'true');
            case 'tcp.flags.fin':
                return pkt.tcp?.fin === (val === '1' || val.toLowerCase() === 'true');
            case 'tcp.flags.rst':
                return pkt.tcp?.rst === (val === '1' || val.toLowerCase() === 'true');
            case 'icmp.type':
                return pkt.icmp?.type === parseInt(val);
            default:
                return false;
        }
    }

    matchFieldContains(pkt, field, value) {
        const val = value.replace(/['"]/g, '').toLowerCase();

        switch (field) {
            case 'http.host':
                return pkt.http?.host?.toLowerCase().includes(val);
            case 'http.uri':
                return pkt.http?.uri?.toLowerCase().includes(val);
            case 'dns.query':
            case 'dns.qry.name':
                return pkt.dns?.query?.toLowerCase().includes(val);
            case 'frame.info':
                return pkt.info?.toLowerCase().includes(val);
            default:
                return false;
        }
    }

    clearFilter() {
        if (this.filterInput) this.filterInput.value = '';
        this.filteredPackets = null;
        this.selectedHost = null;
        this.renderPacketTable();
        this.updateStats();
        this.unhighlightAllNodes();
    }

    filterByHost(ip) {
        // Set filter input
        if (this.filterInput) {
            this.filterInput.value = `ip.addr == ${ip}`;
        }

        // Filter packets by this host
        this.filteredPackets = this.packets.filter(pkt =>
            pkt.src === ip || pkt.dst === ip
        );
        this.selectedHost = ip;

        // Highlight node in topology
        this.highlightNode(ip);

        // Update UI
        this.currentPage = 1;
        this.renderFilteredTable();

        // Show host info in footer
        const host = this.hosts.get(ip);
        const infoEl = document.getElementById('selected-packet-info');
        if (infoEl && host) {
            infoEl.textContent = `Host: ${ip} | ${host.packets} pkts | ${this.formatBytes(host.bytes)}`;
        } else if (infoEl) {
            infoEl.textContent = `Filtered: ${ip} (${this.filteredPackets.length} packets)`;
        }
    }

    highlightNode(ip) {
        if (!this.topologyG) return;

        // Reset all nodes
        this.topologyG.selectAll('.node circle')
            .attr('stroke', '#fff')
            .attr('stroke-width', 2);

        // Highlight selected node
        this.topologyG.selectAll('.node')
            .filter(d => d.id === ip)
            .select('circle')
            .attr('stroke', '#58a6ff')
            .attr('stroke-width', 4);
    }

    unhighlightAllNodes() {
        if (!this.topologyG) return;
        this.topologyG.selectAll('.node circle')
            .attr('stroke', '#fff')
            .attr('stroke-width', 2);
    }

    renderFilteredTable() {
        const packets = this.filteredPackets || this.packets;
        const start = (this.currentPage - 1) * this.pageSize;
        const end = start + this.pageSize;
        const pagePackets = packets.slice(start, end);

        this.packetTbody.innerHTML = '';

        pagePackets.forEach(pkt => {
            const proto = pkt.protocol || 'Unknown';
            const row = document.createElement('tr');
            const colorClass = this.getPacketColorClass(pkt);
            row.className = `proto-${proto.toLowerCase()} ${colorClass}`;
            row.dataset.id = pkt.id;

            const time = this.formatTime(pkt.timestamp);

            row.innerHTML = `
                <td>${pkt.id}</td>
                <td>${time}</td>
                <td>${pkt.src || '-'}</td>
                <td>${pkt.dst || '-'}</td>
                <td>${proto}</td>
                <td>${pkt.length}</td>
                <td>${pkt.info || ''}</td>
            `;

            row.addEventListener('click', () => this.selectPacket(pkt, row));
            this.packetTbody.appendChild(row);
        });

        // Update displayed count
        if (this.statDisplayed) {
            this.statDisplayed.textContent = packets.length;
        }
    }

    selectPacket(pkt, row) {
        document.querySelectorAll('.packet-table tr.selected').forEach(r => r.classList.remove('selected'));
        row.classList.add('selected');
        this.selectedPacket = pkt;
        this.showDetails(pkt);
        this.showHexDump(pkt);
    }

    showDetails(pkt) {
        if (!this.detailPlaceholder || !this.detailContent) return;

        this.detailPlaceholder.style.display = 'none';
        this.detailContent.style.display = 'block';

        // Packet summary header - timestamp is in microseconds
        const timestampMs = pkt.timestamp / 1000;
        const captureDate = new Date(timestampMs);
        const relativeTime = this.formatTime(pkt.timestamp);

        let html = '<div class="detail-summary">';
        html += `<div class="summary-line">
            <span class="summary-label">No.</span>
            <span class="summary-value">${pkt.id}</span>
            <span class="summary-label">Time</span>
            <span class="summary-value">${relativeTime}s</span>
            <span class="summary-label">Length</span>
            <span class="summary-value">${pkt.length} bytes</span>
        </div>`;
        html += `<div class="summary-line">
            <span class="summary-label">Proto</span>
            <span class="summary-value proto proto-${pkt.protocol?.toLowerCase() || 'unknown'}">${pkt.protocol || 'Unknown'}</span>
            <span class="summary-label">Info</span>
            <span class="summary-value">${pkt.info || ''}</span>
        </div>`;
        html += '</div>';

        html += '<div class="detail-tree">';

        // Frame info
        html += this.createTreeSection('Frame', 'frame', [
            { label: 'Frame Number', value: pkt.id },
            { label: 'Frame Length', value: `${pkt.length} bytes on wire` },
            { label: 'Capture Length', value: `${pkt.length} bytes captured` },
            { label: 'Capture Time', value: captureDate.toISOString() },
            { label: 'Epoch Time', value: (pkt.timestamp / 1000000).toFixed(6) }
        ], true);

        // Ethernet layer
        if (pkt.ethernet) {
            const eth = pkt.ethernet;
            html += this.createTreeSection('Ethernet II', 'ethernet', [
                { label: 'Destination', value: eth.dst_mac, type: 'mac-address' },
                { label: 'Source', value: eth.src_mac, type: 'mac-address' },
                { label: 'Type', value: `${this.getEthertypeString(eth.ethertype)} (0x${eth.ethertype.toString(16).padStart(4, '0')})` }
            ], true);
        }

        // IP layer
        if (pkt.ip) {
            const ip = pkt.ip;
            html += this.createTreeSection(`Internet Protocol Version ${ip.version}`, 'ip', [
                { label: 'Version', value: ip.version },
                { label: 'Header Length', value: `${ip.ihl * 4} bytes (${ip.ihl})` },
                { label: 'Differentiated Services', value: `0x${(ip.tos || 0).toString(16).padStart(2, '0')}`, type: 'hex-value' },
                { label: 'Total Length', value: `${ip.total_len} bytes` },
                { label: 'Identification', value: `0x${ip.id.toString(16).padStart(4, '0')} (${ip.id})`, type: 'hex-value' },
                { label: 'Flags', value: this.getIPFlags(ip.flags), type: 'flags' },
                { label: 'Fragment Offset', value: ip.frag_offset || 0 },
                { label: 'Time to Live', value: ip.ttl },
                { label: 'Protocol', value: `${this.getIPProtocolString(ip.protocol)} (${ip.protocol})` },
                { label: 'Header Checksum', value: `0x${ip.checksum.toString(16).padStart(4, '0')}`, type: 'hex-value' },
                { label: 'Source Address', value: ip.src, type: 'ip-address' },
                { label: 'Destination Address', value: ip.dst, type: 'ip-address' }
            ], true);
        }

        // TCP layer
        if (pkt.tcp) {
            const tcp = pkt.tcp;
            const flags = [];
            if (tcp.syn) flags.push('SYN');
            if (tcp.ack_flag) flags.push('ACK');
            if (tcp.fin) flags.push('FIN');
            if (tcp.rst) flags.push('RST');
            if (tcp.psh) flags.push('PSH');
            if (tcp.urg) flags.push('URG');

            html += this.createTreeSection('Transmission Control Protocol', 'tcp', [
                { label: 'Source Port', value: `${tcp.src_port} (${this.getServiceName(tcp.src_port)})`, type: 'port-number' },
                { label: 'Destination Port', value: `${tcp.dst_port} (${this.getServiceName(tcp.dst_port)})`, type: 'port-number' },
                { label: 'Stream Index', value: tcp.stream || 0 },
                { label: 'Sequence Number', value: tcp.seq },
                { label: 'Sequence Number (raw)', value: tcp.seq },
                { label: 'Acknowledgment Number', value: tcp.ack },
                { label: 'Header Length', value: `${(tcp.data_offset || 5) * 4} bytes (${tcp.data_offset || 5})` },
                { label: 'Flags', value: `0x${(tcp.flags || 0).toString(16).padStart(3, '0')} [${flags.join(', ') || 'None'}]`, type: 'flags' },
                { label: 'Window Size', value: tcp.window },
                { label: 'Checksum', value: `0x${tcp.checksum.toString(16).padStart(4, '0')}`, type: 'hex-value' },
                { label: 'Urgent Pointer', value: tcp.urgent || 0 },
                { label: 'Payload', value: `${tcp.payload_len || 0} bytes` }
            ], true);
        }

        // UDP layer
        if (pkt.udp) {
            const udp = pkt.udp;
            html += this.createTreeSection('User Datagram Protocol', 'udp', [
                { label: 'Source Port', value: `${udp.src_port} (${this.getServiceName(udp.src_port)})`, type: 'port-number' },
                { label: 'Destination Port', value: `${udp.dst_port} (${this.getServiceName(udp.dst_port)})`, type: 'port-number' },
                { label: 'Length', value: `${udp.length} bytes` },
                { label: 'Checksum', value: `0x${udp.checksum.toString(16).padStart(4, '0')}`, type: 'hex-value' },
                { label: 'Payload', value: `${udp.payload_len || 0} bytes` }
            ], true);
        }

        // ICMP layer
        if (pkt.icmp) {
            const icmp = pkt.icmp;
            html += this.createTreeSection('Internet Control Message Protocol', 'icmp', [
                { label: 'Type', value: `${icmp.type} (${this.getICMPTypeName(icmp.type)})` },
                { label: 'Code', value: icmp.code },
                { label: 'Checksum', value: `0x${(icmp.checksum || 0).toString(16).padStart(4, '0')}`, type: 'hex-value' },
                { label: 'Identifier', value: icmp.id || 0 },
                { label: 'Sequence', value: icmp.seq || 0 }
            ], true);
        }

        // ARP layer
        if (pkt.arp) {
            const arp = pkt.arp;
            html += this.createTreeSection('Address Resolution Protocol', 'arp', [
                { label: 'Hardware Type', value: `Ethernet (${arp.hw_type || 1})` },
                { label: 'Protocol Type', value: `IPv4 (0x0800)` },
                { label: 'Hardware Size', value: arp.hw_size || 6 },
                { label: 'Protocol Size', value: arp.proto_size || 4 },
                { label: 'Opcode', value: `${arp.opcode === 1 ? 'request' : 'reply'} (${arp.opcode})` },
                { label: 'Sender MAC', value: arp.sender_mac, type: 'mac-address' },
                { label: 'Sender IP', value: arp.sender_ip, type: 'ip-address' },
                { label: 'Target MAC', value: arp.target_mac, type: 'mac-address' },
                { label: 'Target IP', value: arp.target_ip, type: 'ip-address' }
            ], true);
        }

        // DNS layer
        if (pkt.dns) {
            const dns = pkt.dns;
            html += this.createTreeSection('Domain Name System', 'dns', [
                { label: 'Transaction ID', value: `0x${(dns.id || 0).toString(16).padStart(4, '0')}`, type: 'hex-value' },
                { label: 'Flags', value: `0x${(dns.flags || 0).toString(16).padStart(4, '0')}`, type: 'flags' },
                { label: 'Questions', value: dns.qdcount || 0 },
                { label: 'Answer RRs', value: dns.ancount || 0 },
                { label: 'Authority RRs', value: dns.nscount || 0 },
                { label: 'Additional RRs', value: dns.arcount || 0 },
                { label: 'Query', value: dns.query || '-' }
            ], true);
        }

        // HTTP layer
        if (pkt.http) {
            const http = pkt.http;
            html += this.createTreeSection('Hypertext Transfer Protocol', 'http', [
                { label: 'Method', value: http.method || '-' },
                { label: 'URI', value: http.uri || '-' },
                { label: 'Version', value: http.version || '-' },
                { label: 'Host', value: http.host || '-' },
                { label: 'User-Agent', value: http.user_agent || '-' },
                { label: 'Content-Type', value: http.content_type || '-' },
                { label: 'Content-Length', value: http.content_length || '-' }
            ], true);
        }

        html += '</div>';
        this.detailContent.innerHTML = html;

        // Add toggle functionality
        this.detailContent.querySelectorAll('.tree-header').forEach(header => {
            header.addEventListener('click', () => {
                header.parentElement.classList.toggle('collapsed');
            });
        });
    }

    getIPFlags(flags) {
        if (!flags) return '0x00';
        const parts = [];
        if (flags & 0x4000) parts.push("Don't Fragment");
        if (flags & 0x2000) parts.push('More Fragments');
        return parts.length ? parts.join(', ') : 'None';
    }

    getICMPTypeName(type) {
        const types = {
            0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench',
            5: 'Redirect', 8: 'Echo Request', 9: 'Router Advertisement',
            10: 'Router Solicitation', 11: 'Time Exceeded', 12: 'Parameter Problem',
            13: 'Timestamp Request', 14: 'Timestamp Reply'
        };
        return types[type] || 'Unknown';
    }

    getServiceName(port) {
        const services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
            110: 'POP3', 123: 'NTP', 143: 'IMAP', 161: 'SNMP', 443: 'HTTPS',
            445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT'
        };
        return services[port] || (port < 1024 ? 'Well-known' : 'Ephemeral');
    }

    createTreeSection(title, layer, items, expanded = false) {
        const collapsedClass = expanded ? '' : 'collapsed';
        let html = `<div class="tree-section layer-${layer} ${collapsedClass}">`;
        html += `<div class="tree-header"><span class="tree-toggle"></span><span class="tree-title">${title}</span></div>`;
        html += '<div class="tree-content">';
        items.forEach(item => {
            const typeClass = item.type ? ` ${item.type}` : '';
            html += `<div class="tree-item"><span class="tree-label">${item.label}:</span><span class="tree-value${typeClass}">${item.value}</span></div>`;
        });
        html += '</div></div>';
        return html;
    }

    getEthertypeString(type) {
        const types = { 0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6', 0x8100: 'VLAN' };
        return types[type] || 'Unknown';
    }

    getIPProtocolString(proto) {
        const protocols = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 89: 'OSPF' };
        return protocols[proto] || 'Unknown';
    }

    formatTime(timestamp) {
        // timestamp is in microseconds
        if (!this.startTime) return '0.000000';
        const elapsedUs = timestamp - this.startTime;
        const elapsedSec = elapsedUs / 1000000;
        return elapsedSec.toFixed(6);
    }

    formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    }

    updateStats() {
        this.statPackets.textContent = this.packets.length.toLocaleString();
        this.statBytes.textContent = this.formatBytes(this.totalBytes);
        this.statHosts.textContent = this.hosts.size.toLocaleString();

        // Update footer stats as well
        this.updateFooterStats();
    }

    startRateCalculation() {
        setInterval(() => {
            const now = Date.now();
            const elapsed = (now - this.lastRateTime) / 1000;

            if (elapsed > 0) {
                const packetRate = Math.round((this.packets.length - this.lastPacketCount) / elapsed);
                const byteRate = Math.round((this.totalBytes - this.lastByteCount) / elapsed);

                this.statPps.textContent = packetRate.toLocaleString() + ' pps';
                this.statBps.textContent = this.formatBytes(byteRate) + '/s';

                this.lastPacketCount = this.packets.length;
                this.lastByteCount = this.totalBytes;
                this.lastRateTime = now;
            }
        }, 1000);
    }

    clearPackets() {
        this.packets = [];
        this.newestId = 0;
        this.totalBytes = 0;
        this.protocolCounts = {};
        this.sourceCounts = {};
        this.sizeBuckets = { '0-64': 0, '65-128': 0, '129-256': 0, '257-512': 0, '513-1024': 0, '1025+': 0 };
        this.hosts.clear();
        this.nodes.clear();
        this.links.clear();
        this.ioGraphData = [];
        this.currentPage = 1;
        this.startTime = this.capturing ? Date.now() : null;

        this.packetTbody.innerHTML = '';
        this.detailPlaceholder.style.display = 'flex';
        this.detailContent.style.display = 'none';

        this.updateStats();
        this.updatePagination();
        this.updateCharts();
        this.updateTopology();
        this.updateIOGraph();

        fetch('/api/clear', { method: 'POST' }).catch(() => {});
    }

    async savePcap() {
        if (this.packets.length === 0) {
            alert('No packets to save');
            return;
        }

        try {
            const response = await fetch('/api/save');
            if (!response.ok) {
                const err = await response.json();
                alert('Save failed: ' + (err.error || 'Unknown error'));
                return;
            }

            // Get filename from Content-Disposition header
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = 'capture.pcap';
            if (contentDisposition) {
                const match = contentDisposition.match(/filename="(.+)"/);
                if (match) filename = match[1];
            }

            // Download the file
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (err) {
            console.error('Save error:', err);
            alert('Save failed: ' + err.message);
        }
    }

    // Charts initialization
    initCharts() {
        const chartColors = {
            tcp: '#58a6ff',
            udp: '#a371f7',
            icmp: '#d29922',
            arp: '#3fb950',
            dns: '#39c5cf',
            http: '#f85149',
            https: '#3fb950',
            other: '#8b949e'
        };

        // Protocol Pie Chart
        const protocolPieCanvas = document.getElementById('protocol-pie-chart');
        if (protocolPieCanvas) {
            this.protocolPieChart = new Chart(protocolPieCanvas, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: Object.values(chartColors),
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    cutout: '60%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#8b949e',
                                font: { size: 10 },
                                padding: 8,
                                usePointStyle: true,
                                pointStyle: 'circle'
                            }
                        },
                        tooltip: {
                            backgroundColor: '#21262d',
                            titleColor: '#e6edf3',
                            bodyColor: '#8b949e',
                            borderColor: '#30363d',
                            borderWidth: 1,
                            callbacks: {
                                label: (ctx) => {
                                    const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                                    const pct = ((ctx.raw / total) * 100).toFixed(1);
                                    return `${ctx.label}: ${ctx.raw.toLocaleString()} (${pct}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }

        // Ports Bar Chart
        const portsBarCanvas = document.getElementById('ports-bar-chart');
        if (portsBarCanvas) {
            this.portsBarChart = new Chart(portsBarCanvas, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Packets',
                        data: [],
                        backgroundColor: '#58a6ff',
                        borderRadius: 3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: '#21262d',
                            titleColor: '#e6edf3',
                            bodyColor: '#8b949e'
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: { color: '#8b949e', font: { size: 10 } }
                        },
                        y: {
                            grid: { display: false },
                            ticks: { color: '#8b949e', font: { size: 10 } }
                        }
                    }
                }
            });
        }

        // Endpoints Bar Chart
        const endpointsBarCanvas = document.getElementById('endpoints-bar-chart');
        if (endpointsBarCanvas) {
            this.endpointsBarChart = new Chart(endpointsBarCanvas, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Tx',
                            data: [],
                            backgroundColor: '#3fb950',
                            borderRadius: 3
                        },
                        {
                            label: 'Rx',
                            data: [],
                            backgroundColor: '#58a6ff',
                            borderRadius: 3
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top',
                            labels: { color: '#8b949e', font: { size: 10 }, boxWidth: 12 }
                        },
                        tooltip: {
                            backgroundColor: '#21262d',
                            titleColor: '#e6edf3',
                            bodyColor: '#8b949e'
                        }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: '#8b949e', font: { size: 9 }, maxRotation: 45 }
                        },
                        y: {
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: { color: '#8b949e', font: { size: 10 } },
                            stacked: false
                        }
                    }
                }
            });
        }
    }

    updateCharts() {
        // Update protocol pie chart
        if (this.protocolPieChart) {
            const protocols = Object.entries(this.protocolCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
            this.protocolPieChart.data.labels = protocols.map(p => p[0]);
            this.protocolPieChart.data.datasets[0].data = protocols.map(p => p[1]);
            this.protocolPieChart.update('none');
        }
    }

    // Update ports bar chart
    updatePortsChart() {
        if (!this.portsBarChart) return;

        // Collect port statistics
        const portStats = new Map();
        this.packets.forEach(pkt => {
            const ports = [];
            if (pkt.tcp) {
                ports.push(pkt.tcp.src_port, pkt.tcp.dst_port);
            }
            if (pkt.udp) {
                ports.push(pkt.udp.src_port, pkt.udp.dst_port);
            }
            ports.forEach(port => {
                if (port && port < 10000) { // Focus on well-known/common ports
                    portStats.set(port, (portStats.get(port) || 0) + 1);
                }
            });
        });

        const topPorts = Array.from(portStats.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);

        const services = {
            22: 'SSH', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB',
            3389: 'RDP', 8080: 'HTTP-Alt', 3306: 'MySQL', 5432: 'PostgreSQL'
        };

        this.portsBarChart.data.labels = topPorts.map(([port]) => services[port] || `Port ${port}`);
        this.portsBarChart.data.datasets[0].data = topPorts.map(([, count]) => count);
        this.portsBarChart.update('none');
    }

    // Update endpoints bar chart
    updateEndpointsChart() {
        if (!this.endpointsBarChart) return;

        const endpointStats = new Map();
        this.packets.forEach(pkt => {
            if (pkt.src) {
                if (!endpointStats.has(pkt.src)) {
                    endpointStats.set(pkt.src, { tx: 0, rx: 0 });
                }
                endpointStats.get(pkt.src).tx++;
            }
            if (pkt.dst) {
                if (!endpointStats.has(pkt.dst)) {
                    endpointStats.set(pkt.dst, { tx: 0, rx: 0 });
                }
                endpointStats.get(pkt.dst).rx++;
            }
        });

        const topEndpoints = Array.from(endpointStats.entries())
            .sort((a, b) => (b[1].tx + b[1].rx) - (a[1].tx + a[1].rx))
            .slice(0, 8);

        this.endpointsBarChart.data.labels = topEndpoints.map(([ip]) => {
            // Shorten IP for display
            const parts = ip.split('.');
            return parts.length === 4 ? `...${parts[2]}.${parts[3]}` : ip.substring(0, 12);
        });
        this.endpointsBarChart.data.datasets[0].data = topEndpoints.map(([, stats]) => stats.tx);
        this.endpointsBarChart.data.datasets[1].data = topEndpoints.map(([, stats]) => stats.rx);
        this.endpointsBarChart.update('none');
    }

    // Topology
    initTopology() {
        const container = document.getElementById('topology-graph');
        if (!container) return;

        const width = container.clientWidth || 800;
        const height = container.clientHeight || 500;

        this.topologySvg = d3.select(container)
            .append('svg')
            .attr('width', '100%')
            .attr('height', '100%');

        // Add arrow marker for directed links
        this.topologySvg.append('defs').append('marker')
            .attr('id', 'arrowhead')
            .attr('viewBox', '-0 -5 10 10')
            .attr('refX', 20)
            .attr('refY', 0)
            .attr('orient', 'auto')
            .attr('markerWidth', 6)
            .attr('markerHeight', 6)
            .append('path')
            .attr('d', 'M 0,-5 L 10,0 L 0,5')
            .attr('fill', '#48484a');

        this.topologyG = this.topologySvg.append('g');

        // Zoom with smooth transitions
        this.topologyZoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                this.topologyG.attr('transform', event.transform);
            });

        this.topologySvg.call(this.topologyZoom);

        // Create simulation with optimized parameters for stability
        this.simulation = d3.forceSimulation()
            .force('link', d3.forceLink().id(d => d.id).distance(80).strength(0.5))
            .force('charge', d3.forceManyBody().strength(-200).distanceMax(300))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(25).strength(0.7))
            .force('x', d3.forceX(width / 2).strength(0.05))
            .force('y', d3.forceY(height / 2).strength(0.05))
            .velocityDecay(0.4)
            .alphaDecay(0.02);

        // Auto-resize on window resize
        window.addEventListener('resize', () => this.resizeTopology());

        this.topologyAnimate = true;
    }

    updateTopologyData(pkt) {
        if (!pkt.src || !pkt.dst) return;
        if (pkt.src === pkt.dst) return; // Skip self-loops

        // Add/update source node
        if (!this.nodes.has(pkt.src)) {
            this.nodes.set(pkt.src, {
                id: pkt.src,
                type: this.getHostType(pkt.src),
                packets: 0,
                bytes: 0,
                firstSeen: pkt.timestamp,
                lastSeen: pkt.timestamp,
                protocols: new Set()
            });
        }
        const srcNode = this.nodes.get(pkt.src);
        srcNode.packets++;
        srcNode.bytes += pkt.length || 0;
        srcNode.lastSeen = pkt.timestamp;
        if (pkt.protocol) srcNode.protocols.add(pkt.protocol);

        // Add/update destination node
        if (!this.nodes.has(pkt.dst)) {
            this.nodes.set(pkt.dst, {
                id: pkt.dst,
                type: this.getHostType(pkt.dst),
                packets: 0,
                bytes: 0,
                firstSeen: pkt.timestamp,
                lastSeen: pkt.timestamp,
                protocols: new Set()
            });
        }
        const dstNode = this.nodes.get(pkt.dst);
        dstNode.packets++;
        dstNode.bytes += pkt.length || 0;
        dstNode.lastSeen = pkt.timestamp;
        if (pkt.protocol) dstNode.protocols.add(pkt.protocol);

        // Add/update link (bidirectional)
        const linkId = [pkt.src, pkt.dst].sort().join('-');
        if (!this.links.has(linkId)) {
            this.links.set(linkId, {
                source: pkt.src,
                target: pkt.dst,
                packets: 0,
                bytes: 0,
                protocols: new Set()
            });
        }
        const link = this.links.get(linkId);
        link.packets++;
        link.bytes += pkt.length || 0;
        if (pkt.protocol) link.protocols.add(pkt.protocol);

        // Throttle topology updates (adaptive based on node count)
        const updateInterval = this.nodes.size > 100 ? 2000 : (this.nodes.size > 50 ? 1500 : 1000);
        if (!this.topologyUpdatePending) {
            this.topologyUpdatePending = true;
            setTimeout(() => {
                this.updateTopology();
                this.topologyUpdatePending = false;
            }, updateInterval);
        }
    }

    getHostType(ip) {
        if (ip.endsWith('.255') || ip === '255.255.255.255') return 'broadcast';
        if (ip.startsWith('224.') || ip.startsWith('239.')) return 'broadcast';
        if (ip.startsWith('ff') || ip.startsWith('FF')) return 'broadcast'; // IPv6 multicast
        if (ip.endsWith('.1') || ip.endsWith(':1')) return 'gateway';

        // RFC 1918 Private addresses
        if (ip.startsWith('192.168.')) return 'local';
        if (ip.startsWith('10.')) return 'local';
        // 172.16.0.0 - 172.31.255.255
        if (ip.startsWith('172.')) {
            const secondOctet = parseInt(ip.split('.')[1]);
            if (secondOctet >= 16 && secondOctet <= 31) return 'local';
        }
        // Link-local
        if (ip.startsWith('169.254.')) return 'local';
        // Loopback
        if (ip.startsWith('127.')) return 'local';
        // IPv6 private
        if (ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) return 'local';
        if (ip === '::1') return 'local';

        return 'remote';
    }

    updateTopology() {
        if (!this.topologyG || !this.simulation) return;

        const nodes = Array.from(this.nodes.values());
        const links = Array.from(this.links.values());

        // Update links with smooth transitions
        const link = this.topologyG.selectAll('.link')
            .data(links, d => `${d.source.id || d.source}-${d.target.id || d.target}`);

        link.exit()
            .transition().duration(300)
            .attr('stroke-opacity', 0)
            .remove();

        const linkEnter = link.enter()
            .append('line')
            .attr('class', 'link')
            .attr('stroke', d => this.getLinkColor(d))
            .attr('stroke-width', d => Math.min(1 + Math.log(d.packets + 1), 6))
            .attr('stroke-opacity', 0);

        linkEnter.transition().duration(300)
            .attr('stroke-opacity', 0.6);

        // Update existing links
        link.transition().duration(300)
            .attr('stroke-width', d => Math.min(1 + Math.log(d.packets + 1), 6))
            .attr('stroke', d => this.getLinkColor(d));

        // Update nodes with smooth transitions
        const node = this.topologyG.selectAll('.node')
            .data(nodes, d => d.id);

        node.exit()
            .transition().duration(300)
            .attr('opacity', 0)
            .remove();

        const nodeEnter = node.enter()
            .append('g')
            .attr('class', 'node')
            .attr('opacity', 0)
            .call(d3.drag()
                .on('start', (event, d) => {
                    if (!event.active && this.topologyAnimate) this.simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                })
                .on('drag', (event, d) => {
                    d.fx = event.x;
                    d.fy = event.y;
                })
                .on('end', (event, d) => {
                    if (!event.active) this.simulation.alphaTarget(0);
                    // Keep position fixed after drag
                }));

        nodeEnter.transition().duration(300)
            .attr('opacity', 1);

        nodeEnter.append('circle')
            .attr('r', d => Math.min(8 + Math.sqrt(d.packets), 20))
            .attr('fill', d => this.getNodeColor(d.type))
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .style('cursor', 'pointer');

        nodeEnter.append('text')
            .attr('dy', 25)
            .attr('text-anchor', 'middle')
            .attr('fill', '#8b949e')
            .attr('font-size', '10px')
            .text(d => d.id);

        // Add click handler for filtering packets
        nodeEnter.on('click', (event, d) => {
            event.stopPropagation();
            this.filterByHost(d.id);
        });

        // Add double-click handler for info panel
        nodeEnter.on('dblclick', (event, d) => {
            event.stopPropagation();
            this.showTopologyInfo(d);
        });

        // Update topology stats
        this.updateTopologyStats();

        // Update simulation
        this.simulation.nodes(nodes);
        this.simulation.force('link').links(links);
        this.simulation.alpha(0.3).restart();

        this.simulation.on('tick', () => {
            this.topologyG.selectAll('.link')
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            this.topologyG.selectAll('.node')
                .attr('transform', d => `translate(${d.x},${d.y})`);
        });
    }

    getNodeColor(type) {
        const colors = {
            local: '#0a84ff',
            gateway: '#ff9f0a',
            remote: '#30d158',
            broadcast: '#bf5af2'
        };
        return colors[type] || '#98989d';
    }

    getLinkColor(link) {
        // Color by dominant protocol
        if (link.protocols && link.protocols.size > 0) {
            const protos = Array.from(link.protocols);
            if (protos.includes('HTTP') || protos.includes('HTTPS')) return '#fd79a8';
            if (protos.includes('DNS')) return '#a29bfe';
            if (protos.includes('SSH')) return '#00cec9';
            if (protos.includes('TCP')) return '#45b7d1';
            if (protos.includes('UDP')) return '#96ceb4';
            if (protos.includes('ICMP')) return '#ffeaa7';
        }
        return '#48484a';
    }

    resetTopology() {
        if (this.topologySvg) {
            this.topologySvg.transition().duration(500).call(
                d3.zoom().transform,
                d3.zoomIdentity
            );
        }
    }

    centerTopology() {
        if (!this.simulation || !this.topologyG) return;

        const nodes = Array.from(this.nodes.values());
        if (nodes.length === 0) return;

        // Calculate center of all nodes
        const container = document.getElementById('topology-graph');
        const width = container?.clientWidth || 800;
        const height = container?.clientHeight || 500;
        const centerX = width / 2;
        const centerY = height / 2;

        // Move all nodes toward center
        nodes.forEach(node => {
            node.x = centerX + (Math.random() - 0.5) * 200;
            node.y = centerY + (Math.random() - 0.5) * 200;
        });

        // Update simulation with stronger center force
        this.simulation
            .force('center', d3.forceCenter(centerX, centerY).strength(1))
            .alpha(1)
            .restart();

        // Reset zoom to identity
        this.topologySvg.transition().duration(500).call(
            d3.zoom().transform,
            d3.zoomIdentity
        );
    }

    clusterTopology() {
        if (!this.simulation || !this.nodes.size) return;

        const container = document.getElementById('topology-graph');
        const width = container?.clientWidth || 800;
        const height = container?.clientHeight || 500;

        // Group nodes by network subnet (first 3 octets)
        const clusters = new Map();
        this.nodes.forEach((node, ip) => {
            const parts = ip.split('.');
            const subnet = parts.slice(0, 3).join('.');
            if (!clusters.has(subnet)) {
                clusters.set(subnet, []);
            }
            clusters.get(subnet).push(node);
        });

        // Position clusters in a grid
        const clusterCount = clusters.size;
        const cols = Math.ceil(Math.sqrt(clusterCount));
        const cellWidth = width / (cols + 1);
        const cellHeight = height / (Math.ceil(clusterCount / cols) + 1);

        let idx = 0;
        clusters.forEach((nodes, subnet) => {
            const col = idx % cols;
            const row = Math.floor(idx / cols);
            const clusterX = cellWidth * (col + 1);
            const clusterY = cellHeight * (row + 1);

            // Position nodes within cluster
            nodes.forEach((node, i) => {
                const angle = (2 * Math.PI * i) / nodes.length;
                const radius = Math.min(cellWidth, cellHeight) * 0.3;
                node.x = clusterX + radius * Math.cos(angle);
                node.y = clusterY + radius * Math.sin(angle);
                node.fx = node.x;
                node.fy = node.y;
            });
            idx++;
        });

        // Update simulation
        this.simulation.alpha(0.5).restart();

        // Release fixed positions after animation
        setTimeout(() => {
            this.nodes.forEach(node => {
                node.fx = null;
                node.fy = null;
            });
        }, 2000);
    }

    changeLayout(layout) {
        if (!this.simulation) return;

        const container = document.getElementById('topology-graph');
        const width = container?.clientWidth || 800;
        const height = container?.clientHeight || 500;

        switch (layout) {
            case 'force':
                this.simulation
                    .force('charge', d3.forceManyBody().strength(-300))
                    .force('center', d3.forceCenter(width / 2, height / 2));
                break;
            case 'radial':
                this.simulation
                    .force('charge', d3.forceManyBody().strength(-100))
                    .force('center', null)
                    .force('r', d3.forceRadial(Math.min(width, height) / 3, width / 2, height / 2));
                break;
            case 'hierarchical':
                // Simple hierarchical layout based on node type
                const typeOrder = { gateway: 0, local: 1, remote: 2, broadcast: 3 };
                this.nodes.forEach(node => {
                    const order = typeOrder[node.type] || 2;
                    node.fy = height * (order + 1) / 5;
                });
                setTimeout(() => {
                    this.nodes.forEach(node => { node.fy = null; });
                }, 2000);
                break;
        }

        this.simulation.alpha(1).restart();
    }

    resizeTopology() {
        const container = document.getElementById('topology-graph');
        if (container && this.simulation) {
            const width = container.clientWidth;
            const height = container.clientHeight;
            this.simulation.force('center', d3.forceCenter(width / 2, height / 2));
            this.simulation.alpha(0.3).restart();
        }
    }

    toggleLabels(show) {
        if (this.topologyG) {
            this.topologyG.selectAll('.node text').style('display', show ? 'block' : 'none');
        }
    }

    toggleAnimation(animate) {
        this.topologyAnimate = animate;
        if (this.simulation) {
            if (animate) {
                this.simulation.alpha(0.3).restart();
            } else {
                this.simulation.stop();
            }
        }
    }

    searchTopology(query) {
        if (!this.topologyG) return;

        query = query.toLowerCase().trim();

        this.topologyG.selectAll('.node').each(function(d) {
            const node = d3.select(this);
            const matches = !query || d.id.toLowerCase().includes(query);
            node.classed('highlighted', matches && query);
            node.classed('dimmed', query && !matches);
        });

        this.topologyG.selectAll('.link').each(function(d) {
            const link = d3.select(this);
            const sourceId = d.source.id || d.source;
            const targetId = d.target.id || d.target;
            const matches = !query ||
                sourceId.toLowerCase().includes(query) ||
                targetId.toLowerCase().includes(query);
            link.classed('dimmed', query && !matches);
        });
    }

    showTopologyInfo(node) {
        const infoPanel = document.getElementById('topology-info');
        if (!infoPanel) return;

        this.selectedTopologyNode = node;

        // Calculate host statistics
        const hostPackets = this.packets.filter(p => p.src === node.id || p.dst === node.id);
        const totalBytes = hostPackets.reduce((sum, p) => sum + p.length, 0);
        const connections = new Set();
        const protocols = new Set();

        hostPackets.forEach(p => {
            if (p.src === node.id) connections.add(p.dst);
            if (p.dst === node.id) connections.add(p.src);
            if (p.protocol) protocols.add(p.protocol);
        });

        // Find first and last seen times
        let firstSeen = '-', lastSeen = '-';
        if (hostPackets.length > 0) {
            const times = hostPackets.map(p => p.timestamp).sort();
            firstSeen = new Date(times[0] * 1000).toLocaleTimeString();
            lastSeen = new Date(times[times.length - 1] * 1000).toLocaleTimeString();
        }

        // Update info panel
        document.getElementById('info-ip').textContent = node.id;
        document.getElementById('info-type').textContent = node.type.charAt(0).toUpperCase() + node.type.slice(1);
        document.getElementById('info-packets').textContent = hostPackets.length.toLocaleString();
        document.getElementById('info-bytes').textContent = this.formatBytes(totalBytes);
        document.getElementById('info-connections').textContent = connections.size;
        document.getElementById('info-first').textContent = firstSeen;
        document.getElementById('info-last').textContent = lastSeen;
        document.getElementById('info-protocols').textContent = Array.from(protocols).join(', ') || '-';

        infoPanel.style.display = 'block';
    }

    closeTopologyInfo() {
        const infoPanel = document.getElementById('topology-info');
        if (infoPanel) infoPanel.style.display = 'none';
        this.selectedTopologyNode = null;
        this.clearTopologyHighlight();
    }

    filterFromInfo() {
        if (this.selectedTopologyNode) {
            this.filterByHost(this.selectedTopologyNode.id);
            this.closeTopologyInfo();
        }
    }

    highlightFromInfo() {
        if (!this.selectedTopologyNode || !this.topologyG) return;

        const targetId = this.selectedTopologyNode.id;

        // Highlight connected nodes and links
        this.topologyG.selectAll('.node').each(function(d) {
            const node = d3.select(this);
            node.classed('dimmed', d.id !== targetId);
        });

        this.topologyG.selectAll('.link').each(function(d) {
            const link = d3.select(this);
            const sourceId = d.source.id || d.source;
            const targetId2 = d.target.id || d.target;
            const connected = sourceId === targetId || targetId2 === targetId;
            link.classed('dimmed', !connected);

            // Un-dim connected nodes
            if (connected) {
                const connectedId = sourceId === targetId ? targetId2 : sourceId;
                d3.selectAll('.node').filter(n => n.id === connectedId).classed('dimmed', false);
            }
        });

        // Highlight the main node
        this.topologyG.selectAll('.node').filter(d => d.id === targetId).classed('highlighted', true);
    }

    clearTopologyHighlight() {
        if (!this.topologyG) return;
        this.topologyG.selectAll('.node').classed('highlighted', false).classed('dimmed', false);
        this.topologyG.selectAll('.link').classed('dimmed', false);
    }

    updateTopologyStats() {
        const nodesEl = document.getElementById('topo-nodes');
        const linksEl = document.getElementById('topo-links');
        if (nodesEl) nodesEl.textContent = this.nodes.size;
        if (linksEl) linksEl.textContent = this.links.size;
    }

    // IO Graph - Enhanced with filtering and precise timing
    initIOGraph() {
        const canvas = document.getElementById('iograph-canvas');
        if (!canvas) return;

        this.ioGraphChart = new Chart(canvas, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets/interval',
                    data: [],
                    borderColor: '#58a6ff',
                    backgroundColor: 'rgba(88, 166, 255, 0.15)',
                    fill: true,
                    tension: 0,
                    pointRadius: 0,
                    borderWidth: 1.5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: '#21262d',
                        titleColor: '#e6edf3',
                        bodyColor: '#8b949e',
                        borderColor: '#30363d',
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#8b949e', maxTicksLimit: 15, font: { size: 10 } }
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#8b949e', font: { size: 10 } },
                        beginAtZero: true
                    }
                },
                interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                }
            }
        });

        this.ioGraphFilter = '';
        this.ioGraphData = [];
        this.lastIOGraphTime = Date.now();
        this.ioGraphPacketCount = 0;
        this.ioGraphByteCount = 0;
        this.ioGraphInterval = 100; // Default 100ms

        // IO Graph event listeners
        document.getElementById('iograph-apply')?.addEventListener('click', () => {
            this.ioGraphFilter = document.getElementById('iograph-filter')?.value || '';
            this.rebuildIOGraph();
        });

        document.getElementById('iograph-clear')?.addEventListener('click', () => {
            document.getElementById('iograph-filter').value = '';
            this.ioGraphFilter = '';
            this.rebuildIOGraph();
        });

        document.getElementById('iograph-interval')?.addEventListener('change', (e) => {
            this.ioGraphInterval = parseInt(e.target.value);
            this.rebuildIOGraph();
        });

        document.getElementById('iograph-yaxis')?.addEventListener('change', () => {
            this.rebuildIOGraph();
        });

        document.getElementById('iograph-smooth')?.addEventListener('change', (e) => {
            this.ioGraphChart.data.datasets[0].tension = e.target.checked ? 0.4 : 0;
            this.ioGraphChart.update();
        });

        setInterval(() => this.updateIOGraphRealtime(), 100);
    }

    // Rebuild IO graph from packet history with filtering
    rebuildIOGraph() {
        if (!this.ioGraphChart || this.packets.length === 0) return;

        const interval = this.ioGraphInterval;
        const yaxis = document.getElementById('iograph-yaxis')?.value || 'packets';
        const filter = this.ioGraphFilter.toLowerCase().trim();

        // Filter packets if needed
        let filteredPackets = this.packets;
        if (filter) {
            filteredPackets = this.packets.filter(pkt => this.matchesIOGraphFilter(pkt, filter));
        }

        if (filteredPackets.length === 0) {
            this.ioGraphChart.data.labels = [];
            this.ioGraphChart.data.datasets[0].data = [];
            this.ioGraphChart.update();
            this.updateIOGraphStats([]);
            return;
        }

        // Group packets by time interval
        const firstTime = filteredPackets[0].timestamp;
        const lastTime = filteredPackets[filteredPackets.length - 1].timestamp;
        const durationMs = (lastTime - firstTime) / 1000; // Convert to ms

        const buckets = new Map();
        const intervalUs = interval * 1000; // Convert ms to microseconds

        filteredPackets.forEach(pkt => {
            const bucketIndex = Math.floor((pkt.timestamp - firstTime) / intervalUs);
            if (!buckets.has(bucketIndex)) {
                buckets.set(bucketIndex, { packets: 0, bytes: 0 });
            }
            const bucket = buckets.get(bucketIndex);
            bucket.packets++;
            bucket.bytes += pkt.length;
        });

        // Build chart data
        const labels = [];
        const data = [];
        const maxBucket = Math.max(...buckets.keys());

        for (let i = 0; i <= maxBucket; i++) {
            const bucket = buckets.get(i) || { packets: 0, bytes: 0 };
            const timeOffset = (i * interval / 1000).toFixed(interval < 100 ? 3 : 1);
            labels.push(`${timeOffset}s`);

            let value = 0;
            if (yaxis === 'packets') {
                value = bucket.packets;
            } else if (yaxis === 'bytes') {
                value = bucket.bytes;
            } else if (yaxis === 'bits') {
                value = (bucket.bytes * 8) / (interval / 1000); // bits per second
            }
            data.push(value);
        }

        // Limit data points for performance
        const maxPoints = 500;
        if (labels.length > maxPoints) {
            const step = Math.ceil(labels.length / maxPoints);
            const newLabels = [];
            const newData = [];
            for (let i = 0; i < labels.length; i += step) {
                newLabels.push(labels[i]);
                // Sum values in this range
                let sum = 0;
                for (let j = i; j < Math.min(i + step, data.length); j++) {
                    sum += data[j];
                }
                newData.push(sum);
            }
            this.ioGraphChart.data.labels = newLabels;
            this.ioGraphChart.data.datasets[0].data = newData;
        } else {
            this.ioGraphChart.data.labels = labels;
            this.ioGraphChart.data.datasets[0].data = data;
        }

        // Update Y-axis label
        const yaxisLabel = yaxis === 'packets' ? 'Packets' : (yaxis === 'bytes' ? 'Bytes' : 'Bits/s');
        this.ioGraphChart.data.datasets[0].label = `${yaxisLabel}/${interval}ms`;

        this.ioGraphChart.update();
        this.updateIOGraphStats(data);
    }

    matchesIOGraphFilter(pkt, filter) {
        // Simple filter matching
        if (!filter) return true;

        // Protocol filter
        if (pkt.protocol?.toLowerCase() === filter) return true;

        // IP filter
        if (filter.includes('ip.addr')) {
            const match = filter.match(/ip\.addr\s*==\s*([0-9.]+)/);
            if (match) {
                const ip = match[1];
                return pkt.src === ip || pkt.dst === ip;
            }
        }

        if (filter.includes('ip.src')) {
            const match = filter.match(/ip\.src\s*==\s*([0-9.]+)/);
            if (match) return pkt.src === match[1];
        }

        if (filter.includes('ip.dst')) {
            const match = filter.match(/ip\.dst\s*==\s*([0-9.]+)/);
            if (match) return pkt.dst === match[1];
        }

        // Port filter
        if (filter.includes('.port')) {
            const match = filter.match(/(tcp|udp)\.port\s*==\s*(\d+)/);
            if (match) {
                const proto = match[1];
                const port = parseInt(match[2]);
                if (proto === 'tcp' && pkt.tcp) {
                    return pkt.tcp.src_port === port || pkt.tcp.dst_port === port;
                }
                if (proto === 'udp' && pkt.udp) {
                    return pkt.udp.src_port === port || pkt.udp.dst_port === port;
                }
            }
        }

        // Text search in info
        if (pkt.info?.toLowerCase().includes(filter)) return true;

        return false;
    }

    updateIOGraphStats(data) {
        if (data.length === 0) {
            document.getElementById('iograph-max').textContent = '0';
            document.getElementById('iograph-avg').textContent = '0';
            document.getElementById('iograph-total').textContent = '0';
            return;
        }

        const max = Math.max(...data);
        const sum = data.reduce((a, b) => a + b, 0);
        const avg = (sum / data.length).toFixed(1);

        const yaxis = document.getElementById('iograph-yaxis')?.value || 'packets';
        const format = yaxis === 'packets' ? (v => v.toLocaleString()) :
                       (v => this.formatBytes(v));

        document.getElementById('iograph-max').textContent = format(max);
        document.getElementById('iograph-avg').textContent = format(parseFloat(avg));
        document.getElementById('iograph-total').textContent = format(sum);
    }

    updateIOGraphData(pkt) {
        this.ioGraphPacketCount++;
        this.ioGraphByteCount += pkt.length;
    }

    // Real-time update for live capture
    updateIOGraphRealtime() {
        if (!this.ioGraphChart || !this.capturing) return;

        const now = Date.now();
        const elapsed = now - this.lastIOGraphTime;

        if (elapsed >= this.ioGraphInterval) {
            const yaxis = document.getElementById('iograph-yaxis')?.value || 'packets';
            let value = 0;

            if (yaxis === 'packets') {
                value = this.ioGraphPacketCount;
            } else if (yaxis === 'bytes') {
                value = this.ioGraphByteCount;
            } else if (yaxis === 'bits') {
                value = (this.ioGraphByteCount * 8) / (this.ioGraphInterval / 1000);
            }

            const timeLabel = ((now - this.startTime) / 1000).toFixed(1) + 's';
            this.ioGraphChart.data.labels.push(timeLabel);
            this.ioGraphChart.data.datasets[0].data.push(value);

            // Keep max 300 points for real-time view
            if (this.ioGraphChart.data.labels.length > 300) {
                this.ioGraphChart.data.labels.shift();
                this.ioGraphChart.data.datasets[0].data.shift();
            }

            this.ioGraphChart.update('none');
            this.updateIOGraphStats(this.ioGraphChart.data.datasets[0].data);

            this.ioGraphPacketCount = 0;
            this.ioGraphByteCount = 0;
            this.lastIOGraphTime = now;
        }
    }

    updateIOGraph() {
        // Deprecated - using updateIOGraphRealtime instead
    }

    // ============================================
    // Advanced Charts (from PacketSniffer)
    // ============================================

    initAdvancedCharts() {
        // Sub-tab switching
        document.querySelectorAll('.sub-tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchSubTab(e.target));
        });

        // Bandwidth chart
        this.initBandwidthChart();
        document.getElementById('bandwidth-refresh')?.addEventListener('click', () => this.updateBandwidthChart());
        document.getElementById('bandwidth-interval')?.addEventListener('change', () => this.updateBandwidthChart());
        document.getElementById('bandwidth-unit')?.addEventListener('change', () => this.updateBandwidthChart());

        // Interval distribution chart
        this.initIntervalChart();
        document.getElementById('interval-refresh')?.addEventListener('click', () => this.updateIntervalChart());
        document.getElementById('interval-binsize')?.addEventListener('change', () => this.updateIntervalChart());

        // Length distribution chart
        this.initLengthChart();
        document.getElementById('length-refresh')?.addEventListener('click', () => this.updateLengthChart());
        document.getElementById('length-binsize')?.addEventListener('change', () => this.updateLengthChart());
    }

    switchSubTab(tabBtn) {
        const subtabName = tabBtn.dataset.subtab;
        const panel = tabBtn.closest('.iograph-panel');

        // Update tab buttons
        panel.querySelectorAll('.sub-tab').forEach(t => t.classList.remove('active'));
        tabBtn.classList.add('active');

        // Update tab content
        panel.querySelectorAll('.sub-tab-content').forEach(c => c.classList.remove('active'));
        panel.querySelector(`#subtab-${subtabName}`)?.classList.add('active');

        // Refresh chart when switching
        setTimeout(() => {
            if (subtabName === 'bandwidth') {
                this.bandwidthChart?.resize();
                this.updateBandwidthChart();
            } else if (subtabName === 'interval') {
                this.intervalChart?.resize();
                this.updateIntervalChart();
            } else if (subtabName === 'length') {
                this.lengthChart?.resize();
                this.updateLengthChart();
            } else if (subtabName === 'io') {
                this.ioGraphChart?.resize();
            }
        }, 50);
    }

    // Bandwidth Chart (Bytes/sec over time)
    initBandwidthChart() {
        const canvas = document.getElementById('bandwidth-canvas');
        if (!canvas) return;

        this.bandwidthChart = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Bandwidth',
                    data: [],
                    borderColor: '#3fb950',
                    backgroundColor: 'rgba(63, 185, 80, 0.1)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        title: { display: true, text: 'Time (sec)', color: '#8b949e' },
                        ticks: { color: '#8b949e', maxTicksLimit: 20 },
                        grid: { color: 'rgba(139, 148, 158, 0.1)' }
                    },
                    y: {
                        title: { display: true, text: 'Bytes/s', color: '#8b949e' },
                        ticks: { color: '#8b949e' },
                        grid: { color: 'rgba(139, 148, 158, 0.1)' },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    updateBandwidthChart() {
        if (!this.bandwidthChart || this.packets.length < 2) return;

        const interval = parseInt(document.getElementById('bandwidth-interval')?.value || 1000);
        const unit = document.getElementById('bandwidth-unit')?.value || 'bytes';

        // Sort packets by timestamp
        const sorted = [...this.packets].sort((a, b) => a.timestamp - b.timestamp);
        const firstTime = sorted[0].timestamp;
        const lastTime = sorted[sorted.length - 1].timestamp;

        // Create time buckets
        const buckets = new Map();
        sorted.forEach(pkt => {
            const bucket = Math.floor((pkt.timestamp - firstTime) * 1000 / interval);
            if (!buckets.has(bucket)) {
                buckets.set(bucket, 0);
            }
            buckets.set(bucket, buckets.get(bucket) + pkt.length);
        });

        // Convert to rate per second
        const multiplier = 1000 / interval;
        const labels = [];
        const data = [];
        let peak = 0, total = 0;

        const maxBucket = Math.max(...buckets.keys());
        for (let i = 0; i <= maxBucket; i++) {
            const bytes = buckets.get(i) || 0;
            let rate = bytes * multiplier;

            // Convert units
            let value = rate;
            if (unit === 'kbytes') value = rate / 1024;
            else if (unit === 'mbytes') value = rate / (1024 * 1024);
            else if (unit === 'bits') value = rate * 8;
            else if (unit === 'kbits') value = (rate * 8) / 1000;
            else if (unit === 'mbits') value = (rate * 8) / 1000000;

            labels.push((i * interval / 1000).toFixed(1));
            data.push(value);
            if (value > peak) peak = value;
            total += bytes;
        }

        // Update chart
        this.bandwidthChart.data.labels = labels;
        this.bandwidthChart.data.datasets[0].data = data;

        // Update Y axis label
        const unitLabels = {
            'bytes': 'Bytes/s', 'kbytes': 'KB/s', 'mbytes': 'MB/s',
            'bits': 'bits/s', 'kbits': 'Kbps', 'mbits': 'Mbps'
        };
        this.bandwidthChart.options.scales.y.title.text = unitLabels[unit];
        this.bandwidthChart.update();

        // Update stats
        document.getElementById('bandwidth-peak').textContent = this.formatBandwidth(peak, unit);
        document.getElementById('bandwidth-avg').textContent = this.formatBandwidth(data.length > 0 ? data.reduce((a,b) => a+b, 0) / data.length : 0, unit);
        document.getElementById('bandwidth-total').textContent = this.formatBytes(total);
    }

    formatBandwidth(value, unit) {
        if (unit.includes('mbits') || unit.includes('mbytes')) return value.toFixed(2);
        if (unit.includes('kbits') || unit.includes('kbytes')) return value.toFixed(1);
        return Math.round(value).toLocaleString();
    }

    // Interval Distribution Chart (packet arrival intervals)
    initIntervalChart() {
        const canvas = document.getElementById('interval-canvas');
        if (!canvas) return;

        this.intervalChart = new Chart(canvas.getContext('2d'), {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets',
                    data: [],
                    backgroundColor: 'rgba(88, 166, 255, 0.7)',
                    borderColor: '#58a6ff',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        title: { display: true, text: 'Interval (ms)', color: '#8b949e' },
                        ticks: { color: '#8b949e', maxTicksLimit: 30 },
                        grid: { color: 'rgba(139, 148, 158, 0.1)' }
                    },
                    y: {
                        title: { display: true, text: 'Packets', color: '#8b949e' },
                        ticks: { color: '#8b949e' },
                        grid: { color: 'rgba(139, 148, 158, 0.1)' },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    updateIntervalChart() {
        if (!this.intervalChart || this.packets.length < 2) return;

        const binSize = parseFloat(document.getElementById('interval-binsize')?.value || 1);

        // Sort packets and calculate intervals
        const sorted = [...this.packets].sort((a, b) => a.timestamp - b.timestamp);
        const intervals = [];
        for (let i = 1; i < sorted.length; i++) {
            const interval = (sorted[i].timestamp - sorted[i-1].timestamp) * 1000; // to ms
            intervals.push(interval);
        }

        if (intervals.length === 0) return;

        // Create histogram bins
        const bins = new Map();
        intervals.forEach(interval => {
            const bin = Math.floor(interval / binSize) * binSize;
            bins.set(bin, (bins.get(bin) || 0) + 1);
        });

        // Sort and limit to reasonable range (exclude outliers)
        const sortedBins = Array.from(bins.entries()).sort((a, b) => a[0] - b[0]);

        // Take 95th percentile to exclude extreme outliers
        const sortedIntervals = [...intervals].sort((a, b) => a - b);
        const p95 = sortedIntervals[Math.floor(sortedIntervals.length * 0.95)];
        const filteredBins = sortedBins.filter(([bin]) => bin <= p95 * 1.5);

        const labels = filteredBins.map(([bin]) => bin.toFixed(binSize < 1 ? 3 : 1));
        const data = filteredBins.map(([, count]) => count);

        this.intervalChart.data.labels = labels;
        this.intervalChart.data.datasets[0].data = data;

        // Update X axis label based on bin size
        const unitLabel = binSize < 1 ? 'Interval (μs)' : 'Interval (ms)';
        this.intervalChart.options.scales.x.title.text = unitLabel;
        this.intervalChart.update();

        // Calculate stats
        const min = Math.min(...intervals);
        const max = Math.max(...intervals);
        const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / intervals.length;
        const jitter = Math.sqrt(variance);

        document.getElementById('interval-min').textContent = min.toFixed(3) + ' ms';
        document.getElementById('interval-max').textContent = max.toFixed(3) + ' ms';
        document.getElementById('interval-avg').textContent = avg.toFixed(3) + ' ms';
        document.getElementById('interval-jitter').textContent = jitter.toFixed(3) + ' ms';
    }

    // Length Distribution Chart (packet size distribution)
    initLengthChart() {
        const canvas = document.getElementById('length-canvas');
        if (!canvas) return;

        this.lengthChart = new Chart(canvas.getContext('2d'), {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets',
                    data: [],
                    backgroundColor: 'rgba(163, 113, 247, 0.7)',
                    borderColor: '#a371f7',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        title: { display: true, text: 'Packet Length (bytes)', color: '#8b949e' },
                        ticks: { color: '#8b949e', maxTicksLimit: 30 },
                        grid: { color: 'rgba(139, 148, 158, 0.1)' }
                    },
                    y: {
                        title: { display: true, text: 'Packets', color: '#8b949e' },
                        ticks: { color: '#8b949e' },
                        grid: { color: 'rgba(139, 148, 158, 0.1)' },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    updateLengthChart() {
        if (!this.lengthChart || this.packets.length === 0) return;

        const binSize = parseInt(document.getElementById('length-binsize')?.value || 64);

        // Create histogram bins
        const bins = new Map();
        let minLen = Infinity, maxLen = 0, totalLen = 0;

        this.packets.forEach(pkt => {
            const len = pkt.length;
            const bin = Math.floor(len / binSize) * binSize;
            bins.set(bin, (bins.get(bin) || 0) + 1);

            if (len < minLen) minLen = len;
            if (len > maxLen) maxLen = len;
            totalLen += len;
        });

        // Sort bins
        const sortedBins = Array.from(bins.entries()).sort((a, b) => a[0] - b[0]);
        const labels = sortedBins.map(([bin]) => `${bin}-${bin + binSize - 1}`);
        const data = sortedBins.map(([, count]) => count);

        this.lengthChart.data.labels = labels;
        this.lengthChart.data.datasets[0].data = data;
        this.lengthChart.update();

        // Find mode (most common bin)
        let modeCount = 0, modeBin = 0;
        sortedBins.forEach(([bin, count]) => {
            if (count > modeCount) {
                modeCount = count;
                modeBin = bin;
            }
        });

        document.getElementById('length-min').textContent = minLen;
        document.getElementById('length-max').textContent = maxLen;
        document.getElementById('length-avg').textContent = Math.round(totalLen / this.packets.length);
        document.getElementById('length-mode').textContent = `${modeBin}-${modeBin + binSize - 1}`;
    }

    // ============================================
    // Network Scan - Enhanced Nmap-style
    // ============================================

    initScanEventListeners() {
        document.getElementById('scan-btn')?.addEventListener('click', () => this.startNetworkScan());
        document.getElementById('scan-stop-btn')?.addEventListener('click', () => this.stopNetworkScan());
        document.getElementById('scan-preset')?.addEventListener('change', (e) => this.applyScanPreset(e.target.value));
        document.getElementById('scan-port-preset')?.addEventListener('change', (e) => this.applyPortPreset(e.target.value));
        document.getElementById('scan-export-btn')?.addEventListener('click', () => this.exportScanResults());

        // View toggle
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.toggleScanView(e.target.closest('.view-btn')));
        });

        // Filter
        document.getElementById('scan-filter')?.addEventListener('input', (e) => this.filterScanResults(e.target.value));
    }

    applyScanPreset(preset) {
        const targetInput = document.getElementById('scan-target');
        if (!targetInput) return;

        // Detect local network from hosts or interface
        let localNetwork = '192.168.1.0';
        for (const [ip] of this.hosts) {
            if (ip.startsWith('192.168.')) {
                const parts = ip.split('.');
                localNetwork = `${parts[0]}.${parts[1]}.${parts[2]}.0`;
                break;
            } else if (ip.startsWith('10.')) {
                const parts = ip.split('.');
                localNetwork = `${parts[0]}.${parts[1]}.${parts[2]}.0`;
                break;
            } else if (ip.startsWith('172.')) {
                const parts = ip.split('.');
                localNetwork = `${parts[0]}.${parts[1]}.${parts[2]}.0`;
                break;
            }
        }

        switch (preset) {
            case 'local':
                targetInput.value = `${localNetwork}/24`;
                break;
            case 'class-b':
                const classB = localNetwork.split('.').slice(0, 2).join('.') + '.0.0';
                targetInput.value = `${classB}/16`;
                break;
            case 'class-a':
                const classA = localNetwork.split('.')[0] + '.0.0.0';
                targetInput.value = `${classA}/8`;
                break;
            case 'private':
                targetInput.value = '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16';
                break;
        }
    }

    applyPortPreset(preset) {
        const portsInput = document.getElementById('scan-ports');
        if (!portsInput) return;

        switch (preset) {
            case 'top100':
                portsInput.value = '7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157';
                break;
            case 'top1000':
                portsInput.value = '1-1000';
                break;
            case 'common':
                portsInput.value = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080';
                break;
            case 'all':
                portsInput.value = '1-65535';
                break;
        }
    }

    async startNetworkScan() {
        const scanType = document.getElementById('scan-type')?.value || 'discovered';
        const target = document.getElementById('scan-target')?.value;
        const ports = document.getElementById('scan-ports')?.value;
        const osDetect = document.getElementById('scan-os')?.checked;
        const serviceDetect = document.getElementById('scan-service')?.checked;
        const aggressive = document.getElementById('scan-aggressive')?.checked;
        const timing = document.getElementById('scan-timing')?.value || '3';

        // Show discovered hosts mode
        if (scanType === 'discovered') {
            this.showDiscoveredHosts();
            return;
        }

        if (!target) {
            alert('Please enter a target range (e.g., 192.168.1.0/24)');
            return;
        }

        // Calculate total IPs
        const totalIPs = this.calculateTotalIPs(target);
        this.scanStartTime = Date.now();
        this.scanResults = [];

        // Show progress UI
        this.showScanProgress(true);
        this.updateScanProgress(0, totalIPs, 'Initializing scan...');

        try {
            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target: target,
                    type: scanType,
                    ports: ports || null,
                    interface: this.deviceSelect?.value || null,
                    os_detect: osDetect,
                    service_detect: serviceDetect,
                    aggressive: aggressive,
                    timing: parseInt(timing)
                })
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Scan failed');
            }

            // Start polling for results
            this.scanPollInterval = setInterval(() => this.pollScanStatus(), 300);

        } catch (error) {
            console.error('Scan error:', error);
            alert('Scan failed: ' + error.message);
            this.showScanProgress(false);
        }
    }

    calculateTotalIPs(target) {
        let total = 0;
        const ranges = target.split(',').map(t => t.trim());

        ranges.forEach(range => {
            if (range.includes('/')) {
                const prefix = parseInt(range.split('/')[1]);
                total += Math.pow(2, 32 - prefix);
            } else if (range.includes('-')) {
                // Handle IP range like 192.168.1.1-100
                const match = range.match(/(\d+)-(\d+)$/);
                if (match) {
                    total += parseInt(match[2]) - parseInt(match[1]) + 1;
                } else {
                    total += 1;
                }
            } else {
                total += 1;
            }
        });

        return total;
    }

    async pollScanStatus() {
        try {
            const statusRes = await fetch('/api/scan/status');
            const status = await statusRes.json();

            if (status.running) {
                this.updateScanProgress(
                    status.current || 0,
                    status.total || 1,
                    `Scanning ${status.current_ip || '...'}`,
                    status.hosts_up || 0
                );
            }

            // Fetch current results
            const resultsRes = await fetch('/api/scan/results');
            const results = await resultsRes.json();

            if (results.hosts && results.hosts.length > 0) {
                this.scanResults = results.hosts;
                this.renderScanResults(results.hosts);
                this.updateScanSummary(results);
            }

            // Stop polling if scan is done
            if (!status.running && this.scanPollInterval) {
                clearInterval(this.scanPollInterval);
                this.scanPollInterval = null;
                this.finishScan(results);
            }

        } catch (error) {
            console.error('Poll error:', error);
        }
    }

    updateScanProgress(current, total, text, hostsUp = 0) {
        const percent = total > 0 ? ((current / total) * 100).toFixed(1) : 0;
        const elapsed = (Date.now() - this.scanStartTime) / 1000;
        const rate = current > 0 ? current / elapsed : 0;
        const remaining = rate > 0 ? (total - current) / rate : 0;

        document.getElementById('scan-progress-fill').style.width = `${percent}%`;
        document.getElementById('scan-progress-percent').textContent = `${percent}%`;
        document.getElementById('scan-stats').textContent = `${current}/${total} hosts (${hostsUp} up)`;
        document.getElementById('scan-progress-text').textContent = text;
        document.getElementById('scan-eta').textContent = remaining > 0 ?
            `ETA: ${this.formatDuration(remaining)}` : 'ETA: calculating...';
    }

    formatDuration(seconds) {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
        return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
    }

    showScanProgress(show) {
        const progress = document.getElementById('scan-progress');
        const info = document.getElementById('scan-info-text');
        const scanBtn = document.getElementById('scan-btn');
        const stopBtn = document.getElementById('scan-stop-btn');

        if (progress) progress.style.display = show ? 'block' : 'none';
        if (info) info.style.display = show ? 'none' : 'flex';
        if (scanBtn) scanBtn.disabled = show;
        if (stopBtn) stopBtn.disabled = !show;
    }

    finishScan(results) {
        this.showScanProgress(false);
        const elapsed = (Date.now() - this.scanStartTime) / 1000;

        // Update summary
        document.getElementById('summary-time').textContent = this.formatDuration(elapsed);

        // Show summary and view toggle
        document.getElementById('scan-summary').style.display = 'flex';
        document.getElementById('scan-view-toggle').style.display = 'flex';

        // Update info
        const info = document.getElementById('scan-info-text');
        if (info) {
            info.innerHTML = `
                <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
                Scan complete in ${this.formatDuration(elapsed)}. Found ${results.hosts?.length || 0} hosts.
            `;
        }
    }

    updateScanSummary(results) {
        const hosts = results.hosts || [];
        const hostsUp = hosts.filter(h => h.status === 'up' || h.status === 'online').length;
        const hostsDown = hosts.length - hostsUp;
        const openPorts = hosts.reduce((sum, h) => sum + (h.ports?.filter(p => p.status === 'open').length || 0), 0);

        document.getElementById('summary-total').textContent = hosts.length;
        document.getElementById('summary-up').textContent = hostsUp;
        document.getElementById('summary-down').textContent = hostsDown;
        document.getElementById('summary-ports').textContent = openPorts;

        // Show summary panel
        document.getElementById('scan-summary').style.display = 'flex';
    }

    renderScanResults(hosts) {
        const hostGrid = document.getElementById('host-grid');
        const hostTbody = document.getElementById('host-tbody');

        if (!hostGrid) return;

        // Render grid view
        hostGrid.innerHTML = '';
        hosts.forEach(host => {
            const card = this.createHostCard(host);
            hostGrid.appendChild(card);
        });

        // Render table view
        if (hostTbody) {
            hostTbody.innerHTML = '';
            hosts.forEach(host => {
                const row = this.createHostRow(host);
                hostTbody.appendChild(row);
            });
        }

        // Show view toggle
        document.getElementById('scan-view-toggle').style.display = 'flex';
    }

    createHostCard(host) {
        const card = document.createElement('div');
        const status = host.status === 'up' || host.status === 'online' ? 'up' : 'down';
        card.className = `host-card ${status}`;
        card.dataset.ip = host.ip;

        const hostType = this.getHostType(host.ip);
        const rtt = host.rtt_ms ? `${host.rtt_ms.toFixed(1)}ms` : (host.rtt_us ? `${(host.rtt_us/1000).toFixed(1)}ms` : '-');

        let portsHtml = '';
        if (host.ports && host.ports.length > 0) {
            const openPorts = host.ports.filter(p => p.status === 'open');
            if (openPorts.length > 0) {
                portsHtml = `
                    <div class="host-ports">
                        <h5>Open Ports (${openPorts.length})</h5>
                        <div class="port-list">
                            ${openPorts.slice(0, 10).map(p => `
                                <span class="port-tag open">${p.port}${p.service ? '/' + p.service : ''}</span>
                            `).join('')}
                            ${openPorts.length > 10 ? `<span class="port-tag">+${openPorts.length - 10} more</span>` : ''}
                        </div>
                    </div>
                `;
            }
        }

        let osHtml = '';
        if (host.os) {
            osHtml = `
                <div class="stat-row">
                    <span class="stat-label">OS:</span>
                    <span class="stat-value">${host.os}</span>
                </div>
            `;
        }

        card.innerHTML = `
            <div class="host-header">
                <div class="host-ip">${host.ip}</div>
                <span class="host-status ${status}">${status.toUpperCase()}</span>
            </div>
            ${host.hostname ? `<div class="host-hostname">${host.hostname}</div>` : ''}
            ${host.mac ? `<div class="host-mac">${host.mac}${host.vendor ? ' (' + host.vendor + ')' : ''}</div>` : ''}
            <div class="host-stats">
                <div class="stat-row">
                    <span class="stat-label">Type:</span>
                    <span class="stat-value">${hostType}</span>
                </div>
                <div class="stat-row">
                    <span class="stat-label">RTT:</span>
                    <span class="stat-value">${rtt}</span>
                </div>
                ${osHtml}
            </div>
            ${portsHtml}
        `;

        card.addEventListener('click', () => this.selectScanHost(host));
        return card;
    }

    createHostRow(host) {
        const row = document.createElement('tr');
        const status = host.status === 'up' || host.status === 'online' ? 'up' : 'down';
        row.className = status;
        row.dataset.ip = host.ip;

        const openPorts = host.ports?.filter(p => p.status === 'open') || [];
        const portsStr = openPorts.slice(0, 5).map(p => p.port).join(', ') +
            (openPorts.length > 5 ? ` (+${openPorts.length - 5})` : '');
        const rtt = host.rtt_ms ? `${host.rtt_ms.toFixed(1)}ms` : '-';

        row.innerHTML = `
            <td><strong>${host.ip}</strong></td>
            <td>${host.hostname || '-'}</td>
            <td><span class="status-badge ${status}">${status.toUpperCase()}</span></td>
            <td>${host.mac || '-'}</td>
            <td>${rtt}</td>
            <td>${portsStr || '-'}</td>
            <td>${host.os || '-'}</td>
        `;

        row.addEventListener('click', () => this.selectScanHost(host));
        return row;
    }

    selectScanHost(host) {
        // Highlight selected
        document.querySelectorAll('.host-card, #host-tbody tr').forEach(el => el.classList.remove('selected'));
        document.querySelectorAll(`[data-ip="${host.ip}"]`).forEach(el => el.classList.add('selected'));

        // Filter packets
        this.filterByHost(host.ip);

        // Show details
        const infoEl = document.getElementById('selected-packet-info');
        if (infoEl) {
            const openPorts = host.ports?.filter(p => p.status === 'open').length || 0;
            infoEl.textContent = `Host: ${host.ip} | Status: ${host.status} | Open Ports: ${openPorts}`;
        }
    }

    toggleScanView(btn) {
        const view = btn.dataset.view;
        document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const grid = document.getElementById('host-grid');
        const table = document.getElementById('host-table-container');

        if (view === 'grid') {
            grid.style.display = 'grid';
            table.style.display = 'none';
        } else {
            grid.style.display = 'none';
            table.style.display = 'block';
        }
    }

    filterScanResults(query) {
        const q = query.toLowerCase();
        document.querySelectorAll('.host-card, #host-tbody tr').forEach(el => {
            const ip = el.dataset.ip || '';
            const text = el.textContent.toLowerCase();
            el.style.display = (ip.includes(q) || text.includes(q)) ? '' : 'none';
        });
    }

    showDiscoveredHosts() {
        const hosts = Array.from(this.hosts.values())
            .sort((a, b) => b.packets - a.packets)
            .map(h => ({
                ip: h.ip,
                mac: h.mac,
                status: 'up',
                packets: h.packets,
                bytes: h.bytes,
                protocols: Array.from(h.protocols || [])
            }));

        this.scanResults = hosts;
        this.renderDiscoveredHosts(hosts);

        // Update UI
        document.getElementById('scan-summary').style.display = 'flex';
        document.getElementById('summary-total').textContent = hosts.length;
        document.getElementById('summary-up').textContent = hosts.length;
        document.getElementById('summary-down').textContent = '0';
        document.getElementById('summary-ports').textContent = '-';
        document.getElementById('summary-time').textContent = '-';
        document.getElementById('scan-view-toggle').style.display = 'flex';

        const info = document.getElementById('scan-info-text');
        if (info) {
            info.innerHTML = `
                <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
                Showing ${hosts.length} hosts discovered from packet capture
            `;
        }
    }

    renderDiscoveredHosts(hosts) {
        const hostGrid = document.getElementById('host-grid');
        const hostTbody = document.getElementById('host-tbody');

        if (!hostGrid) return;
        hostGrid.innerHTML = '';

        if (hosts.length === 0) {
            hostGrid.innerHTML = '<div class="empty-state">No hosts discovered. Start packet capture to discover hosts.</div>';
            return;
        }

        hosts.forEach(host => {
            const card = document.createElement('div');
            card.className = 'host-card up';
            card.dataset.ip = host.ip;

            const hostType = this.getHostType(host.ip);
            const protocols = (host.protocols || []).slice(0, 5).join(', ');

            card.innerHTML = `
                <div class="host-header">
                    <div class="host-ip">${host.ip}</div>
                    <span class="host-status ${hostType}">${hostType}</span>
                </div>
                ${host.mac ? `<div class="host-mac">${host.mac}</div>` : ''}
                <div class="host-stats">
                    <div class="stat-row">
                        <span class="stat-label">Packets:</span>
                        <span class="stat-value">${host.packets?.toLocaleString() || 0}</span>
                    </div>
                    <div class="stat-row">
                        <span class="stat-label">Bytes:</span>
                        <span class="stat-value">${this.formatBytes(host.bytes || 0)}</span>
                    </div>
                    ${protocols ? `
                    <div class="stat-row">
                        <span class="stat-label">Protocols:</span>
                        <span class="stat-value protocols">${protocols}</span>
                    </div>
                    ` : ''}
                </div>
            `;

            card.addEventListener('click', () => this.filterByHost(host.ip));
            hostGrid.appendChild(card);
        });

        // Table view
        if (hostTbody) {
            hostTbody.innerHTML = '';
            hosts.forEach(host => {
                const row = document.createElement('tr');
                row.dataset.ip = host.ip;
                row.innerHTML = `
                    <td><strong>${host.ip}</strong></td>
                    <td>-</td>
                    <td><span class="status-badge up">UP</span></td>
                    <td>${host.mac || '-'}</td>
                    <td>-</td>
                    <td>${host.packets?.toLocaleString() || 0} pkts</td>
                    <td>-</td>
                `;
                row.addEventListener('click', () => this.filterByHost(host.ip));
                hostTbody.appendChild(row);
            });
        }
    }

    async stopNetworkScan() {
        if (this.scanPollInterval) {
            clearInterval(this.scanPollInterval);
            this.scanPollInterval = null;
        }

        try {
            await fetch('/api/scan/stop', { method: 'POST' });
        } catch (e) {
            console.error('Stop scan error:', e);
        }

        this.showScanProgress(false);
        const info = document.getElementById('scan-info-text');
        if (info) {
            info.innerHTML = `
                <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
                Scan stopped
            `;
        }
    }

    exportScanResults() {
        if (!this.scanResults || this.scanResults.length === 0) {
            alert('No scan results to export');
            return;
        }

        // Generate CSV
        let csv = 'IP,Hostname,Status,MAC,Vendor,RTT(ms),OS,Open Ports\n';
        this.scanResults.forEach(host => {
            const openPorts = (host.ports || []).filter(p => p.status === 'open').map(p => p.port).join(';');
            csv += `"${host.ip}","${host.hostname || ''}","${host.status}","${host.mac || ''}","${host.vendor || ''}","${host.rtt_ms || ''}","${host.os || ''}","${openPorts}"\n`;
        });

        // Download
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ==========================================
    // Context Menu
    // ==========================================
    initContextMenu() {
        const menu = document.getElementById('packet-context-menu');
        if (!menu) return;

        // Hide on click outside
        document.addEventListener('click', () => {
            menu.style.display = 'none';
        });

        // Handle menu item clicks
        menu.querySelectorAll('.context-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                const action = item.dataset.action;
                this.handleContextAction(action);
                menu.style.display = 'none';
            });
        });

        // Setup right-click on packet table
        document.getElementById('packet-tbody')?.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            const row = e.target.closest('tr');
            if (row && row.dataset.id) {
                const pkt = this.packets.find(p => p.id == row.dataset.id);
                if (pkt) {
                    this.contextPacket = pkt;
                    menu.style.left = `${e.clientX}px`;
                    menu.style.top = `${e.clientY}px`;
                    menu.style.display = 'block';
                }
            }
        });
    }

    handleContextAction(action) {
        const pkt = this.contextPacket;
        if (!pkt) return;

        switch (action) {
            case 'follow-tcp':
            case 'follow-udp':
                this.followStream(pkt, action === 'follow-tcp' ? 'TCP' : 'UDP');
                break;
            case 'filter-conversation':
                this.filterInput.value = `(ip.src == ${pkt.src} && ip.dst == ${pkt.dst}) || (ip.src == ${pkt.dst} && ip.dst == ${pkt.src})`;
                this.applyFilter();
                break;
            case 'filter-src':
                this.filterInput.value = `ip.src == ${pkt.src}`;
                this.applyFilter();
                break;
            case 'filter-dst':
                this.filterInput.value = `ip.dst == ${pkt.dst}`;
                this.applyFilter();
                break;
            case 'filter-proto':
                this.filterInput.value = pkt.protocol?.toLowerCase() || '';
                this.applyFilter();
                break;
            case 'copy-summary':
                this.copySummary(pkt);
                break;
            case 'copy-hex':
                this.copyHex();
                break;
            case 'mark-packet':
                this.toggleMarkPacket(pkt);
                break;
        }
    }

    // ==========================================
    // Follow Stream
    // ==========================================
    followStream(pkt, proto) {
        if (!pkt.tcp && !pkt.udp) return;

        const srcPort = pkt.tcp?.src_port || pkt.udp?.src_port;
        const dstPort = pkt.tcp?.dst_port || pkt.udp?.dst_port;

        // Find all packets in this stream
        const streamPackets = this.packets.filter(p => {
            if (proto === 'TCP' && !p.tcp) return false;
            if (proto === 'UDP' && !p.udp) return false;

            const pSrcPort = p.tcp?.src_port || p.udp?.src_port;
            const pDstPort = p.tcp?.dst_port || p.udp?.dst_port;

            return (p.src === pkt.src && p.dst === pkt.dst && pSrcPort === srcPort && pDstPort === dstPort) ||
                   (p.src === pkt.dst && p.dst === pkt.src && pSrcPort === dstPort && pDstPort === srcPort);
        });

        this.currentStreamPackets = streamPackets;
        this.streamClient = { ip: pkt.src, port: srcPort };
        this.streamServer = { ip: pkt.dst, port: dstPort };

        // Update dialog
        document.getElementById('stream-title').textContent = `Follow ${proto} Stream (${pkt.src}:${srcPort} ↔ ${pkt.dst}:${dstPort})`;

        const clientCount = streamPackets.filter(p => p.src === pkt.src).length;
        const serverCount = streamPackets.length - clientCount;
        document.getElementById('stream-info').textContent = `${clientCount} client packets, ${serverCount} server packets (${streamPackets.length} total)`;

        this.updateStreamFormat('ascii');
        document.getElementById('stream-dialog').style.display = 'flex';
    }

    updateStreamFormat(format) {
        if (!this.currentStreamPackets) return;

        const content = document.getElementById('stream-content');
        let html = '';

        this.currentStreamPackets.forEach(pkt => {
            const isClient = pkt.src === this.streamClient.ip;
            const className = isClient ? 'client' : 'server';
            const payload = pkt.tcp?.payload || pkt.udp?.payload || '';

            if (format === 'ascii') {
                const ascii = this.payloadToAscii(payload);
                if (ascii) {
                    html += `<span class="${className}">${this.escapeHtml(ascii)}</span>\n`;
                }
            } else if (format === 'hex') {
                const hex = this.payloadToHex(payload);
                if (hex) {
                    html += `<span class="${className}">${hex}</span>\n`;
                }
            } else {
                html += `<span class="${className}">${payload || ''}</span>\n`;
            }
        });

        content.innerHTML = html || '<span style="color: var(--text-muted)">No payload data in stream</span>';
    }

    payloadToAscii(payload) {
        if (!payload) return '';
        // Assuming payload is base64 or hex string
        try {
            if (/^[0-9a-fA-F]+$/.test(payload)) {
                let str = '';
                for (let i = 0; i < payload.length; i += 2) {
                    const charCode = parseInt(payload.substr(i, 2), 16);
                    str += (charCode >= 32 && charCode < 127) ? String.fromCharCode(charCode) : '.';
                }
                return str;
            }
            return atob(payload);
        } catch {
            return payload;
        }
    }

    payloadToHex(payload) {
        if (!payload) return '';
        if (/^[0-9a-fA-F]+$/.test(payload)) {
            return payload.toUpperCase().match(/.{1,2}/g)?.join(' ') || '';
        }
        try {
            const decoded = atob(payload);
            let hex = '';
            for (let i = 0; i < decoded.length; i++) {
                hex += decoded.charCodeAt(i).toString(16).padStart(2, '0').toUpperCase() + ' ';
            }
            return hex;
        } catch {
            return payload;
        }
    }

    hideStreamDialog() {
        document.getElementById('stream-dialog').style.display = 'none';
    }

    copyStreamContent() {
        const content = document.getElementById('stream-content').innerText;
        navigator.clipboard.writeText(content);
    }

    saveStreamContent() {
        const content = document.getElementById('stream-content').innerText;
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `stream_${new Date().toISOString().slice(0, 19).replace(/[:-]/g, '')}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ==========================================
    // Coloring Rules
    // ==========================================
    showColoringDialog() {
        document.getElementById('coloring-dialog').style.display = 'flex';
    }

    hideColoringDialog() {
        document.getElementById('coloring-dialog').style.display = 'none';
    }

    applyColoringRules() {
        this.coloringRules = {};
        document.querySelectorAll('.coloring-rule input[type="checkbox"]').forEach(cb => {
            this.coloringRules[cb.dataset.rule] = cb.checked;
        });
        this.renderPacketTable();
        this.hideColoringDialog();
    }

    resetColoringRules() {
        document.querySelectorAll('.coloring-rule input[type="checkbox"]').forEach(cb => {
            cb.checked = true;
        });
    }

    getPacketColorClass(pkt) {
        if (!this.coloringRules) {
            this.coloringRules = { http: true, https: true, dns: true, 'tcp-syn': true, 'tcp-rst': true, icmp: true, arp: true };
        }

        if (pkt.marked) return 'marked';

        const proto = pkt.protocol?.toLowerCase();

        if (this.coloringRules.http && (proto === 'http' || (pkt.tcp?.dst_port === 80 || pkt.tcp?.src_port === 80))) {
            return 'color-http';
        }
        if (this.coloringRules.https && (proto === 'https' || proto === 'tls' || pkt.tcp?.dst_port === 443 || pkt.tcp?.src_port === 443)) {
            return 'color-https';
        }
        if (this.coloringRules.dns && (proto === 'dns' || pkt.udp?.dst_port === 53 || pkt.udp?.src_port === 53)) {
            return 'color-dns';
        }
        if (this.coloringRules['tcp-rst'] && pkt.tcp?.rst) {
            return 'color-tcp-rst';
        }
        if (this.coloringRules['tcp-syn'] && pkt.tcp?.syn && !pkt.tcp?.ack_flag) {
            return 'color-tcp-syn';
        }
        if (this.coloringRules.icmp && proto === 'icmp') {
            return 'color-icmp';
        }
        if (this.coloringRules.arp && proto === 'arp') {
            return 'color-arp';
        }

        return '';
    }

    toggleMarkPacket(pkt) {
        pkt.marked = !pkt.marked;
        this.renderPacketTable();
    }

    copySummary(pkt) {
        const summary = `No.${pkt.id} ${new Date(pkt.timestamp * 1000).toISOString()} ${pkt.src} → ${pkt.dst} ${pkt.protocol} ${pkt.length}B ${pkt.info || ''}`;
        navigator.clipboard.writeText(summary);
    }

    // ==========================================
    // PCAP File Load (from PacketSniffer)
    // ==========================================
    async loadPcapFile(event) {
        const file = event.target.files[0];
        if (!file) return;

        // Show progress
        this.showProgress(0, 'Loading PCAP...');
        this.updateStatusInfo(`Loading ${file.name}...`);

        try {
            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch('/api/pcap/load', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Upload failed');
            }

            const result = await response.json();

            this.hideProgress();
            this.updateStatusInfo(`Loaded ${result.packets_loaded} packets from ${file.name}`);

            // Refresh packets from server
            this.packets = [];
            this.newestId = 0;
            await this.pollPackets();
            this.renderPacketTable();
            this.updateStats();
            this.updateCharts();
            this.updateTopology();

        } catch (error) {
            this.hideProgress();
            this.updateStatusInfo('Load failed: ' + error.message);
            alert('Failed to load PCAP: ' + error.message);
        }

        // Reset file input
        event.target.value = '';
    }

    // ==========================================
    // Packet Replay (from PacketGenerator)
    // ==========================================
    async replayPackets() {
        if (this.packets.length === 0) {
            alert('No packets to replay');
            return;
        }

        const device = this.deviceSelect.value;
        if (!device) {
            alert('Please select a network interface first');
            return;
        }

        // Confirm replay
        const count = this.filteredPackets ? this.filteredPackets.length : this.packets.length;
        if (!confirm(`Replay ${count} packet(s) on ${device}?\n\nThis will inject the packets into the network.`)) {
            return;
        }

        this.showProgress(0, 'Replaying...');
        this.updateStatusInfo('Replaying packets...');

        try {
            const response = await fetch('/api/packet/inject', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    device: device,
                    replay: true,
                    repeat: 1
                })
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Replay failed');
            }

            const result = await response.json();
            this.hideProgress();
            this.updateStatusInfo(`Replayed ${result.packets_sent} packets`);

        } catch (error) {
            this.hideProgress();
            this.updateStatusInfo('Replay failed: ' + error.message);
            alert('Replay failed: ' + error.message);
        }
    }

    // ==========================================
    // Export Functions
    // ==========================================
    exportPcap() {
        // Request server to save current capture as PCAP
        fetch('/api/capture/save', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if (data.file) {
                    // Download the file
                    const a = document.createElement('a');
                    a.href = `/api/capture/download?file=${encodeURIComponent(data.file)}`;
                    a.download = data.file;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                } else {
                    alert('Failed to save PCAP: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(err => {
                console.error('Export PCAP failed:', err);
                alert('Export failed. Check console for details.');
            });
    }

    exportCSV() {
        const packets = this.currentFilter ? this.filteredPackets : this.packets;
        if (packets.length === 0) {
            alert('No packets to export');
            return;
        }

        let csv = 'No,Time,Source,Destination,Protocol,Length,Info\n';
        packets.forEach(pkt => {
            const time = new Date(pkt.timestamp * 1000).toISOString();
            const info = (pkt.info || '').replace(/"/g, '""');
            csv += `${pkt.id},"${time}","${pkt.src}","${pkt.dst}","${pkt.protocol}",${pkt.length},"${info}"\n`;
        });

        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `packets_${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    escapeHtml(str) {
        return str.replace(/&/g, '&amp;')
                  .replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;')
                  .replace(/"/g, '&quot;');
    }

    // ==========================================
    // Zoom Functions (like PacketSniffer)
    // ==========================================
    zoomIn() {
        if (!this.currentZoom) this.currentZoom = 100;
        if (this.currentZoom < 200) {
            this.currentZoom += 10;
            this.applyZoom();
        }
    }

    zoomOut() {
        if (!this.currentZoom) this.currentZoom = 100;
        if (this.currentZoom > 50) {
            this.currentZoom -= 10;
            this.applyZoom();
        }
    }

    resetZoom() {
        this.currentZoom = 100;
        this.applyZoom();
    }

    applyZoom() {
        const packetTable = document.querySelector('.packet-table');
        const detailTree = document.querySelector('.detail-tree');
        const hexDump = document.querySelector('.hex-dump');

        const fontSize = (this.currentZoom / 100) * 12; // base font size 12px

        if (packetTable) {
            packetTable.style.fontSize = `${fontSize}px`;
        }
        if (detailTree) {
            detailTree.style.fontSize = `${fontSize}px`;
        }
        if (hexDump) {
            hexDump.style.fontSize = `${fontSize}px`;
        }

        // Update status
        this.updateStatusInfo(`Zoom: ${this.currentZoom}%`);
    }

    // ==========================================
    // Fullscreen Mode (F11)
    // ==========================================
    toggleFullscreen() {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen().catch(err => {
                console.log('Fullscreen error:', err);
            });
        } else {
            document.exitFullscreen();
        }
    }

    // ==========================================
    // Packet Navigation (like PacketSniffer)
    // ==========================================
    selectPreviousPacket() {
        if (this.selectedPacketIndex > 0) {
            this.selectedPacketIndex--;
            const packets = this.filteredPackets || this.packets;
            if (packets[this.selectedPacketIndex]) {
                this.selectPacket(packets[this.selectedPacketIndex]);
                this.ensurePacketVisible(this.selectedPacketIndex);
            }
        }
    }

    selectNextPacket() {
        const packets = this.filteredPackets || this.packets;
        if (this.selectedPacketIndex < packets.length - 1) {
            this.selectedPacketIndex++;
            if (packets[this.selectedPacketIndex]) {
                this.selectPacket(packets[this.selectedPacketIndex]);
                this.ensurePacketVisible(this.selectedPacketIndex);
            }
        }
    }

    goToFirstPacket() {
        this.selectedPacketIndex = 0;
        const packets = this.filteredPackets || this.packets;
        if (packets.length > 0) {
            this.selectPacket(packets[0]);
            this.currentPage = 1;
            this.renderPacketTable();
            this.updatePagination();
        }
    }

    goToLastPacket() {
        const packets = this.filteredPackets || this.packets;
        if (packets.length > 0) {
            this.selectedPacketIndex = packets.length - 1;
            this.selectPacket(packets[this.selectedPacketIndex]);
            this.currentPage = Math.ceil(packets.length / this.pageSize);
            this.renderPacketTable();
            this.updatePagination();
        }
    }

    ensurePacketVisible(index) {
        const pageForIndex = Math.floor(index / this.pageSize) + 1;
        if (pageForIndex !== this.currentPage) {
            this.currentPage = pageForIndex;
            this.renderPacketTable();
            this.updatePagination();
        }
        // Scroll to the row within the current page
        const rowIndex = index % this.pageSize;
        const row = this.packetTbody?.children[rowIndex];
        if (row) {
            row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
    }

    // ==========================================
    // Progress Bar (like PacketSniffer)
    // ==========================================
    showProgress(percent, text = '') {
        const container = document.getElementById('progress-container');
        const bar = document.getElementById('progress-bar');
        const textEl = document.getElementById('progress-text');

        if (container && bar && textEl) {
            container.style.display = 'flex';
            bar.style.width = `${percent}%`;
            textEl.textContent = text || `${percent}%`;
        }
    }

    hideProgress() {
        const container = document.getElementById('progress-container');
        if (container) {
            container.style.display = 'none';
        }
    }

    // ==========================================
    // Enhanced Status Bar Updates
    // ==========================================
    updateStatusInfo(message) {
        const infoEl = document.getElementById('selected-packet-info');
        if (infoEl) {
            infoEl.textContent = message;
        }
    }

    updateCaptureState(state) {
        const stateEl = document.getElementById('capture-state');
        const indicator = document.getElementById('capture-indicator');

        if (stateEl) {
            stateEl.textContent = state;
        }
        if (indicator) {
            indicator.className = 'status-indicator';
            if (state === 'Running') {
                indicator.classList.add('running');
            } else if (state === 'Stopped') {
                indicator.classList.add('stopped');
            }
        }
    }

    updateFooterStats() {
        const totalPackets = document.getElementById('stat-total-packets');
        const totalBytes = document.getElementById('stat-total-bytes');
        const displayed = document.getElementById('stat-displayed');

        if (totalPackets) {
            totalPackets.textContent = this.packets.length.toLocaleString();
        }
        if (totalBytes) {
            totalBytes.textContent = this.formatBytes(this.totalBytes);
        }
        if (displayed) {
            const displayCount = this.filteredPackets ? this.filteredPackets.length : this.packets.length;
            displayed.textContent = displayCount.toLocaleString();
        }
    }
}

// Initialize
const netmap = new NetMap();
