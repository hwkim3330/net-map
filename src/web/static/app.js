/**
 * Net-Map - Web UI Application
 */

class NetMap {
    constructor() {
        this.packets = [];
        this.lastId = 0;
        this.capturing = false;
        this.selectedPacket = null;
        this.pollInterval = null;
        this.startTime = null;

        this.initElements();
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
        this.statusText = document.getElementById('status-text');
        this.captureStatus = document.getElementById('capture-status');
        this.detailPanel = document.getElementById('detail-panel');
        this.detailContent = document.getElementById('detail-content');
        this.detailClose = document.getElementById('detail-close');
    }

    initEventListeners() {
        this.startBtn.addEventListener('click', () => this.startCapture());
        this.stopBtn.addEventListener('click', () => this.stopCapture());
        this.clearBtn.addEventListener('click', () => this.clearPackets());
        this.detailClose.addEventListener('click', () => this.hideDetails());

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideDetails();
            }
        });
    }

    async loadDevices() {
        try {
            this.setStatus('Loading interfaces...');
            const response = await fetch('/api/devices');
            const devices = await response.json();

            this.deviceSelect.innerHTML = '<option value="">Select Interface...</option>';
            devices.forEach((dev, index) => {
                const option = document.createElement('option');
                option.value = dev.name;
                const label = dev.ip ? `${dev.description} (${dev.ip})` : dev.description;
                option.textContent = label;
                if (dev.loopback) option.textContent += ' [Loopback]';
                this.deviceSelect.appendChild(option);
            });

            this.setStatus(`Found ${devices.length} interfaces`);
        } catch (error) {
            this.setStatus('Error loading interfaces');
            console.error('Failed to load devices:', error);
        }
    }

    async startCapture() {
        const device = this.deviceSelect.value;
        if (!device) {
            alert('Please select a network interface');
            return;
        }

        try {
            this.capturing = true;
            this.startTime = Date.now();
            this.updateCaptureUI();
            this.setStatus(`Capturing on ${device}...`);

            // Start polling for packets
            this.pollInterval = setInterval(() => this.pollPackets(), 500);

        } catch (error) {
            this.capturing = false;
            this.updateCaptureUI();
            this.setStatus('Error starting capture');
            console.error('Failed to start capture:', error);
        }
    }

    stopCapture() {
        this.capturing = false;
        this.updateCaptureUI();

        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }

        this.setStatus('Capture stopped');
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

        } catch (error) {
            console.error('Failed to poll packets:', error);
        }
    }

    addPacket(pkt) {
        this.packets.push(pkt);

        const row = document.createElement('tr');
        row.className = `proto-${pkt.protocol.toLowerCase()}`;
        row.dataset.id = pkt.id;

        const time = this.formatTime(pkt.timestamp);

        row.innerHTML = `
            <td class="col-no">${pkt.id}</td>
            <td class="col-time">${time}</td>
            <td class="col-src">${pkt.src || '-'}</td>
            <td class="col-dst">${pkt.dst || '-'}</td>
            <td class="col-proto">${pkt.protocol}</td>
            <td class="col-len">${pkt.length}</td>
            <td class="col-info">${pkt.info}</td>
        `;

        row.addEventListener('click', () => this.selectPacket(pkt, row));

        this.packetTbody.appendChild(row);

        // Auto-scroll to bottom
        const container = document.querySelector('.packet-list-container');
        container.scrollTop = container.scrollHeight;
    }

    selectPacket(pkt, row) {
        // Remove previous selection
        document.querySelectorAll('.packet-table tbody tr.selected').forEach(r => {
            r.classList.remove('selected');
        });

        row.classList.add('selected');
        this.selectedPacket = pkt;
        this.showDetails(pkt);
    }

    showDetails(pkt) {
        this.detailPanel.classList.add('visible');

        this.detailContent.innerHTML = `
            <div class="detail-row"><span class="detail-label">Packet ID:</span>${pkt.id}</div>
            <div class="detail-row"><span class="detail-label">Timestamp:</span>${new Date(pkt.timestamp / 1000).toISOString()}</div>
            <div class="detail-row"><span class="detail-label">Source:</span>${pkt.src || 'N/A'}</div>
            <div class="detail-row"><span class="detail-label">Destination:</span>${pkt.dst || 'N/A'}</div>
            <div class="detail-row"><span class="detail-label">Protocol:</span>${pkt.protocol}</div>
            <div class="detail-row"><span class="detail-label">Length:</span>${pkt.length} bytes</div>
            <div class="detail-row"><span class="detail-label">Info:</span>${pkt.info}</div>
        `;
    }

    hideDetails() {
        this.detailPanel.classList.remove('visible');
        this.selectedPacket = null;

        document.querySelectorAll('.packet-table tbody tr.selected').forEach(r => {
            r.classList.remove('selected');
        });
    }

    clearPackets() {
        this.packets = [];
        this.lastId = 0;
        this.packetTbody.innerHTML = '';
        this.hideDetails();
        this.updateStats(0);
        this.setStatus('Packets cleared');
    }

    updateCaptureUI() {
        this.startBtn.disabled = this.capturing;
        this.stopBtn.disabled = !this.capturing;
        this.deviceSelect.disabled = this.capturing;
        this.filterInput.disabled = this.capturing;

        this.captureStatus.textContent = this.capturing ? 'Capturing' : 'Stopped';
        this.captureStatus.className = 'capture-status ' + (this.capturing ? 'running' : 'stopped');
    }

    updateStats(total) {
        this.packetCount.textContent = this.formatNumber(total || this.packets.length);

        const totalBytes = this.packets.reduce((sum, p) => sum + p.length, 0);
        this.byteCount.textContent = this.formatBytes(totalBytes);
    }

    setStatus(text) {
        this.statusText.textContent = text;
    }

    formatTime(timestamp) {
        if (!this.startTime) return '0.000000';

        // timestamp is in microseconds
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
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
        return (bytes / 1024 / 1024 / 1024).toFixed(1) + ' GB';
    }
}

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    window.netmap = new NetMap();
});
