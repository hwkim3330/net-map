/**
 * Net-Map - Modern Web UI Application
 * Features: Real-time charts, Protocol distribution, Network topology
 */

class NetMap {
    constructor() {
        this.packets = [];
        this.lastId = 0;
        this.capturing = false;
        this.selectedPacket = null;
        this.pollInterval = null;
        this.startTime = null;
        this.lastPollTime = Date.now();
        this.lastPacketCount = 0;
        this.lastByteCount = 0;

        // Chart data
        this.trafficData = [];
        this.protocolCounts = {};
        this.sourceCounts = {};
        this.sizeBuckets = { '0-64': 0, '65-128': 0, '129-256': 0, '257-512': 0, '513-1024': 0, '1025+': 0 };

        // Topology data
        this.nodes = new Map();
        this.links = new Map();

        this.initElements();
        this.initCharts();
        this.initTopology();
        this.initEventListeners();
        this.loadDevices();
    }

    initElements() {
        this.deviceSelect = document.getElementById('device-select');
        this.filterInput = document.getElementById('filter-input');
        this.startBtn = document.getElementById('start-btn');
        this.stopBtn = document.getElementById('stop-btn');
        this.clearBtn = document.getElementById('clear-btn');
        this.packetTbody = document.getElementById('packet-tbody');
        this.packetCount = document.getElementById('packet-count');
        this.byteCount = document.getElementById('byte-count');
        this.ppsCount = document.getElementById('pps-count');
        this.bpsCount = document.getElementById('bps-count');
        this.captureIndicator = document.getElementById('capture-indicator');
        this.captureStatusText = document.getElementById('capture-status-text');
        this.detailPanel = document.getElementById('detail-panel');
        this.detailContent = document.getElementById('detail-content');
        this.detailClose = document.getElementById('detail-close');
        this.searchInput = document.getElementById('search-input');
        this.chartInterval = document.getElementById('chart-interval');
    }

    initCharts() {
        // Traffic Over Time Chart
        const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
        this.trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Packets/s',
                        data: [],
                        borderColor: '#007AFF',
                        backgroundColor: 'rgba(0, 122, 255, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        borderWidth: 2
                    },
                    {
                        label: 'KB/s',
                        data: [],
                        borderColor: '#34C759',
                        backgroundColor: 'rgba(52, 199, 89, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        borderWidth: 2,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { intersect: false, mode: 'index' },
                plugins: {
                    legend: { position: 'top', labels: { usePointStyle: true, padding: 20 } }
                },
                scales: {
                    x: { display: true, grid: { display: false } },
                    y: {
                        display: true,
                        position: 'left',
                        grid: { color: 'rgba(0,0,0,0.05)' },
                        title: { display: true, text: 'Packets/s' }
                    },
                    y1: {
                        display: true,
                        position: 'right',
                        grid: { display: false },
                        title: { display: true, text: 'KB/s' }
                    }
                }
            }
        });

        // Protocol Distribution Chart
        const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
        this.protocolChart = new Chart(protocolCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#007AFF', '#34C759', '#FF9500', '#FF3B30',
                        '#AF52DE', '#5AC8FA', '#FFCC00', '#FF2D55'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: { position: 'right', labels: { usePointStyle: true, padding: 12 } }
                }
            }
        });

        // Top Sources Chart
        const sourcesCtx = document.getElementById('sources-chart').getContext('2d');
        this.sourcesChart = new Chart(sourcesCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets',
                    data: [],
                    backgroundColor: '#007AFF',
                    borderRadius: 4,
                    barThickness: 20
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: 'rgba(0,0,0,0.05)' } },
                    y: { grid: { display: false } }
                }
            }
        });

        // Packet Size Distribution Chart
        const sizeCtx = document.getElementById('size-chart').getContext('2d');
        this.sizeChart = new Chart(sizeCtx, {
            type: 'bar',
            data: {
                labels: ['0-64', '65-128', '129-256', '257-512', '513-1024', '1025+'],
                datasets: [{
                    label: 'Packets',
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#5AC8FA', '#34C759', '#FFCC00', '#FF9500', '#FF3B30', '#AF52DE'
                    ],
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false }, title: { display: true, text: 'Bytes' } },
                    y: { grid: { color: 'rgba(0,0,0,0.05)' }, title: { display: true, text: 'Count' } }
                }
            }
        });
    }

    initTopology() {
        const container = document.getElementById('topology-graph');
        const width = container.clientWidth || 800;
        const height = container.clientHeight || 500;

        this.topologySvg = d3.select('#topology-graph')
            .append('svg')
            .attr('width', '100%')
            .attr('height', '100%')
            .attr('viewBox', [0, 0, width, height]);

        // Add zoom behavior
        const g = this.topologySvg.append('g');
        this.topologyG = g;

        this.topologySvg.call(d3.zoom()
            .extent([[0, 0], [width, height]])
            .scaleExtent([0.5, 4])
            .on('zoom', (event) => {
                g.attr('transform', event.transform);
            }));

        // Create groups for links and nodes
        this.linkGroup = g.append('g').attr('class', 'links');
        this.nodeGroup = g.append('g').attr('class', 'nodes');

        // Force simulation
        this.simulation = d3.forceSimulation()
            .force('link', d3.forceLink().id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-200))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(40));

        // Reset button
        document.getElementById('topology-reset').addEventListener('click', () => {
            this.topologySvg.transition().duration(500).call(
                d3.zoom().transform,
                d3.zoomIdentity
            );
        });
    }

    initEventListeners() {
        this.startBtn.addEventListener('click', () => this.startCapture());
        this.stopBtn.addEventListener('click', () => this.stopCapture());
        this.clearBtn.addEventListener('click', () => this.clearPackets());
        this.detailClose.addEventListener('click', () => this.hideDetails());

        // Tab navigation
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tab = e.currentTarget.dataset.tab;
                this.switchTab(tab);
            });
        });

        // Search
        this.searchInput.addEventListener('input', (e) => {
            this.filterPackets(e.target.value);
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideDetails();
            }
        });
    }

    switchTab(tabName) {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `tab-${tabName}`);
        });

        // Resize topology if switching to it
        if (tabName === 'topology') {
            this.updateTopology();
        }
    }

    async loadDevices() {
        try {
            const response = await fetch('/api/devices');
            const devices = await response.json();

            this.deviceSelect.innerHTML = '<option value="">Select Interface...</option>';
            devices.forEach((dev) => {
                const option = document.createElement('option');
                option.value = dev.name;
                const label = dev.ip ? `${dev.description} (${dev.ip})` : dev.description;
                option.textContent = label;
                if (dev.loopback) option.textContent += ' [Loopback]';
                this.deviceSelect.appendChild(option);
            });
        } catch (error) {
            console.error('Failed to load devices:', error);
        }
    }

    async startCapture() {
        const device = this.deviceSelect.value;
        if (!device) {
            alert('Please select a network interface');
            return;
        }

        const filter = this.filterInput.value.trim();

        try {
            const response = await fetch('/api/capture/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ device, filter })
            });

            const result = await response.json();

            if (result.error) {
                alert('Error: ' + result.error);
                return;
            }

            this.capturing = true;
            this.startTime = Date.now();
            this.lastPollTime = Date.now();
            this.lastPacketCount = 0;
            this.lastByteCount = 0;
            this.updateCaptureUI();

            // Start polling
            this.pollInterval = setInterval(() => this.pollPackets(), 500);

        } catch (error) {
            console.error('Failed to start capture:', error);
        }
    }

    async stopCapture() {
        try {
            await fetch('/api/capture/stop', { method: 'POST' });
        } catch (error) {
            console.error('Failed to stop capture:', error);
        }

        this.capturing = false;
        this.updateCaptureUI();

        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }

    async pollPackets() {
        if (!this.capturing) return;

        try {
            const response = await fetch(`/api/packets?from=${this.lastId + 1}&limit=100`);
            const data = await response.json();

            if (data.packets && data.packets.length > 0) {
                data.packets.forEach(pkt => this.addPacket(pkt));
                this.lastId = data.newest_id;
            }

            this.updateStats(data.total);
            this.updateCharts();

        } catch (error) {
            console.error('Failed to poll packets:', error);
        }
    }

    addPacket(pkt) {
        this.packets.push(pkt);

        // Update protocol counts
        const proto = pkt.protocol || 'Unknown';
        this.protocolCounts[proto] = (this.protocolCounts[proto] || 0) + 1;

        // Update source counts
        if (pkt.src) {
            this.sourceCounts[pkt.src] = (this.sourceCounts[pkt.src] || 0) + 1;
        }

        // Update size buckets
        const size = pkt.length || 0;
        if (size <= 64) this.sizeBuckets['0-64']++;
        else if (size <= 128) this.sizeBuckets['65-128']++;
        else if (size <= 256) this.sizeBuckets['129-256']++;
        else if (size <= 512) this.sizeBuckets['257-512']++;
        else if (size <= 1024) this.sizeBuckets['513-1024']++;
        else this.sizeBuckets['1025+']++;

        // Update topology
        this.updateTopologyData(pkt);

        // Add to table
        const row = document.createElement('tr');
        row.className = `proto-${proto.toLowerCase()}`;
        row.dataset.id = pkt.id;

        const time = this.formatTime(pkt.timestamp);

        row.innerHTML = `
            <td class="col-no">${pkt.id}</td>
            <td class="col-time">${time}</td>
            <td class="col-src">${pkt.src || '-'}</td>
            <td class="col-dst">${pkt.dst || '-'}</td>
            <td class="col-proto">${proto}</td>
            <td class="col-len">${pkt.length}</td>
            <td class="col-info">${pkt.info || ''}</td>
        `;

        row.addEventListener('click', () => this.selectPacket(pkt, row));
        this.packetTbody.appendChild(row);

        // Auto-scroll
        const container = document.querySelector('.packet-table-container');
        if (container) {
            container.scrollTop = container.scrollHeight;
        }
    }

    updateTopologyData(pkt) {
        if (!pkt.src || !pkt.dst) return;

        // Add/update source node
        if (!this.nodes.has(pkt.src)) {
            this.nodes.set(pkt.src, { id: pkt.src, type: 'source', packets: 0 });
        }
        this.nodes.get(pkt.src).packets++;

        // Add/update destination node
        if (!this.nodes.has(pkt.dst)) {
            this.nodes.set(pkt.dst, { id: pkt.dst, type: 'destination', packets: 0 });
        }
        const dstNode = this.nodes.get(pkt.dst);
        dstNode.packets++;
        if (dstNode.type === 'source') dstNode.type = 'both';

        // Check if source was previously only destination
        const srcNode = this.nodes.get(pkt.src);
        if (srcNode.type === 'destination') srcNode.type = 'both';

        // Add/update link
        const linkKey = `${pkt.src}->${pkt.dst}`;
        if (!this.links.has(linkKey)) {
            this.links.set(linkKey, { source: pkt.src, target: pkt.dst, packets: 0 });
        }
        this.links.get(linkKey).packets++;
    }

    updateTopology() {
        const nodesArray = Array.from(this.nodes.values());
        const linksArray = Array.from(this.links.values());

        // Update links
        const link = this.linkGroup.selectAll('.topology-link')
            .data(linksArray, d => `${d.source.id || d.source}-${d.target.id || d.target}`);

        link.exit().remove();

        link.enter()
            .append('line')
            .attr('class', 'topology-link')
            .merge(link)
            .attr('stroke-width', d => Math.min(Math.sqrt(d.packets) + 1, 5));

        // Update nodes
        const node = this.nodeGroup.selectAll('.topology-node')
            .data(nodesArray, d => d.id);

        node.exit().remove();

        const nodeEnter = node.enter()
            .append('g')
            .attr('class', 'topology-node')
            .call(d3.drag()
                .on('start', (event, d) => {
                    if (!event.active) this.simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                })
                .on('drag', (event, d) => {
                    d.fx = event.x;
                    d.fy = event.y;
                })
                .on('end', (event, d) => {
                    if (!event.active) this.simulation.alphaTarget(0);
                    d.fx = null;
                    d.fy = null;
                }));

        nodeEnter.append('circle')
            .attr('r', 8);

        nodeEnter.append('text')
            .attr('dy', -12)
            .attr('text-anchor', 'middle');

        const nodeUpdate = nodeEnter.merge(node);

        nodeUpdate.select('circle')
            .attr('fill', d => {
                if (d.type === 'source') return '#007AFF';
                if (d.type === 'destination') return '#34C759';
                return '#FF9500';
            })
            .attr('r', d => Math.min(Math.sqrt(d.packets) + 6, 20));

        nodeUpdate.select('text')
            .text(d => d.id.length > 15 ? d.id.slice(0, 15) + '...' : d.id);

        // Update simulation
        this.simulation.nodes(nodesArray);
        this.simulation.force('link').links(linksArray);
        this.simulation.alpha(0.3).restart();

        this.simulation.on('tick', () => {
            this.linkGroup.selectAll('.topology-link')
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            this.nodeGroup.selectAll('.topology-node')
                .attr('transform', d => `translate(${d.x},${d.y})`);
        });
    }

    selectPacket(pkt, row) {
        document.querySelectorAll('.packet-table tbody tr.selected').forEach(r => {
            r.classList.remove('selected');
        });

        row.classList.add('selected');
        this.selectedPacket = pkt;
        this.showDetails(pkt);
    }

    showDetails(pkt) {
        this.detailPanel.classList.add('visible');

        let html = '<div class="detail-tree">';

        // Frame info
        html += this.createTreeSection('Frame', [
            { label: 'Frame Number', value: pkt.id },
            { label: 'Frame Length', value: `${pkt.length} bytes` },
            { label: 'Capture Time', value: new Date(pkt.timestamp / 1000).toISOString() }
        ], true);

        // Ethernet layer
        if (pkt.ethernet) {
            const eth = pkt.ethernet;
            const ethertypeStr = this.getEthertypeString(eth.ethertype);
            html += this.createTreeSection('Ethernet II', [
                { label: 'Destination', value: eth.dst_mac },
                { label: 'Source', value: eth.src_mac },
                { label: 'Type', value: `${ethertypeStr} (0x${eth.ethertype.toString(16).padStart(4, '0')})` }
            ], true);
        }

        // IP layer
        if (pkt.ip) {
            const ip = pkt.ip;
            const protoStr = this.getIPProtocolString(ip.protocol);
            html += this.createTreeSection('Internet Protocol Version 4', [
                { label: 'Version', value: ip.version },
                { label: 'Header Length', value: `${ip.ihl * 4} bytes (${ip.ihl})` },
                { label: 'Differentiated Services', value: `0x${ip.tos.toString(16).padStart(2, '0')}` },
                { label: 'Total Length', value: ip.total_len },
                { label: 'Identification', value: `0x${ip.id.toString(16).padStart(4, '0')} (${ip.id})` },
                { label: 'Flags', value: `0x${ip.flags.toString(16)}` },
                { label: 'Fragment Offset', value: ip.frag_offset },
                { label: 'Time to Live', value: ip.ttl },
                { label: 'Protocol', value: `${protoStr} (${ip.protocol})` },
                { label: 'Header Checksum', value: `0x${ip.checksum.toString(16).padStart(4, '0')}` },
                { label: 'Source Address', value: ip.src },
                { label: 'Destination Address', value: ip.dst }
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
            const flagStr = flags.length > 0 ? flags.join(', ') : 'None';

            html += this.createTreeSection('Transmission Control Protocol', [
                { label: 'Source Port', value: tcp.src_port },
                { label: 'Destination Port', value: tcp.dst_port },
                { label: 'Sequence Number', value: tcp.seq },
                { label: 'Acknowledgment Number', value: tcp.ack },
                { label: 'Header Length', value: `${tcp.data_offset * 4} bytes (${tcp.data_offset})` },
                { label: 'Flags', value: `0x${tcp.flags.toString(16).padStart(3, '0')} (${flagStr})` },
                { label: 'Window', value: tcp.window },
                { label: 'Checksum', value: `0x${tcp.checksum.toString(16).padStart(4, '0')}` },
                { label: 'Urgent Pointer', value: tcp.urgent },
                { label: 'Payload Length', value: `${tcp.payload_len} bytes` }
            ], true);
        }

        // UDP layer
        if (pkt.udp) {
            const udp = pkt.udp;
            html += this.createTreeSection('User Datagram Protocol', [
                { label: 'Source Port', value: udp.src_port },
                { label: 'Destination Port', value: udp.dst_port },
                { label: 'Length', value: udp.length },
                { label: 'Checksum', value: `0x${udp.checksum.toString(16).padStart(4, '0')}` },
                { label: 'Payload Length', value: `${udp.payload_len} bytes` }
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

    createTreeSection(title, items, expanded = false) {
        const collapsedClass = expanded ? '' : 'collapsed';
        let html = `<div class="tree-section ${collapsedClass}">`;
        html += `<div class="tree-header"><span class="tree-toggle"></span><span class="tree-title">${title}</span></div>`;
        html += '<div class="tree-content">';
        items.forEach(item => {
            html += `<div class="tree-item"><span class="tree-label">${item.label}:</span><span class="tree-value">${item.value}</span></div>`;
        });
        html += '</div></div>';
        return html;
    }

    getEthertypeString(type) {
        const types = { 0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6', 0x8100: 'VLAN', 0x88A8: 'QinQ' };
        return types[type] || 'Unknown';
    }

    getIPProtocolString(proto) {
        const protocols = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF' };
        return protocols[proto] || 'Unknown';
    }

    hideDetails() {
        this.detailPanel.classList.remove('visible');
        this.selectedPacket = null;

        document.querySelectorAll('.packet-table tbody tr.selected').forEach(r => {
            r.classList.remove('selected');
        });
    }

    filterPackets(query) {
        const rows = this.packetTbody.querySelectorAll('tr');
        const lowerQuery = query.toLowerCase();

        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(lowerQuery) ? '' : 'none';
        });
    }

    async clearPackets() {
        try {
            await fetch('/api/clear', { method: 'POST' });
        } catch (error) {
            console.error('Failed to clear:', error);
        }

        this.packets = [];
        this.lastId = 0;
        this.protocolCounts = {};
        this.sourceCounts = {};
        this.sizeBuckets = { '0-64': 0, '65-128': 0, '129-256': 0, '257-512': 0, '513-1024': 0, '1025+': 0 };
        this.trafficData = [];
        this.nodes.clear();
        this.links.clear();

        this.packetTbody.innerHTML = '';
        this.hideDetails();
        this.updateStats(0);
        this.updateCharts();
        this.updateTopology();
    }

    updateCaptureUI() {
        this.startBtn.disabled = this.capturing;
        this.stopBtn.disabled = !this.capturing;
        this.deviceSelect.disabled = this.capturing;
        this.filterInput.disabled = this.capturing;

        this.captureStatusText.textContent = this.capturing ? 'Capturing' : 'Stopped';
        this.captureIndicator.classList.toggle('active', this.capturing);
    }

    updateStats(total) {
        const now = Date.now();
        const elapsed = (now - this.lastPollTime) / 1000;
        const currentPackets = total || this.packets.length;
        const totalBytes = this.packets.reduce((sum, p) => sum + (p.length || 0), 0);

        // Calculate rates
        const pps = elapsed > 0 ? Math.round((currentPackets - this.lastPacketCount) / elapsed) : 0;
        const bps = elapsed > 0 ? (totalBytes - this.lastByteCount) / elapsed : 0;

        this.packetCount.textContent = this.formatNumber(currentPackets);
        this.byteCount.textContent = this.formatBytes(totalBytes);
        this.ppsCount.textContent = this.formatNumber(pps);
        this.bpsCount.textContent = this.formatBytes(bps) + '/s';

        // Store traffic data point
        if (this.capturing) {
            const timeLabel = new Date().toLocaleTimeString();
            this.trafficData.push({ time: timeLabel, pps, bps: bps / 1024 });
            if (this.trafficData.length > 60) {
                this.trafficData.shift();
            }
        }

        this.lastPollTime = now;
        this.lastPacketCount = currentPackets;
        this.lastByteCount = totalBytes;
    }

    updateCharts() {
        // Traffic chart
        this.trafficChart.data.labels = this.trafficData.map(d => d.time);
        this.trafficChart.data.datasets[0].data = this.trafficData.map(d => d.pps);
        this.trafficChart.data.datasets[1].data = this.trafficData.map(d => d.bps);
        this.trafficChart.update('none');

        // Protocol chart
        const protocols = Object.entries(this.protocolCounts).sort((a, b) => b[1] - a[1]);
        this.protocolChart.data.labels = protocols.map(p => p[0]);
        this.protocolChart.data.datasets[0].data = protocols.map(p => p[1]);
        this.protocolChart.update('none');

        // Sources chart (top 5)
        const sources = Object.entries(this.sourceCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
        this.sourcesChart.data.labels = sources.map(s => s[0]);
        this.sourcesChart.data.datasets[0].data = sources.map(s => s[1]);
        this.sourcesChart.update('none');

        // Size chart
        this.sizeChart.data.datasets[0].data = Object.values(this.sizeBuckets);
        this.sizeChart.update('none');

        // Update topology periodically
        if (this.packets.length % 10 === 0) {
            this.updateTopology();
        }
    }

    formatTime(timestamp) {
        if (!this.startTime) return '0.000000';
        const seconds = (timestamp / 1000000) % 86400;
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        return `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toFixed(6).padStart(9, '0')}`;
    }

    formatNumber(n) {
        return n.toLocaleString();
    }

    formatBytes(bytes) {
        if (bytes < 1024) return bytes.toFixed(0) + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
        return (bytes / 1024 / 1024 / 1024).toFixed(1) + ' GB';
    }
}

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    window.netmap = new NetMap();
});
