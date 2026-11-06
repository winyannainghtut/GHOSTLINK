/* Ghostlink mesh map: draws mesh nodes and the links between them as SVG. Shared, unchanged, by
   the desktop app and the server dashboard (a test checks both copies are identical). No
   dependencies, no inline styles: shapes get classes styled by each app's CSS. */
'use strict';
(function (global) {
  const NS = 'http://www.w3.org/2000/svg';
  const WIDTH = 760, HEIGHT = 480, RADIUS = 24;

  function svg(tag, attrs, parent) {
    const node = document.createElementNS(NS, tag);
    for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, String(value));
    if (parent) parent.append(node);
    return node;
  }

  // Every active pair of mesh nodes is linked, so a ring reads best: relays first (at the top),
  // then the others by ID; nodes waiting or disabled come last. Large meshes use two rings.
  // The same mesh always lays out the same; saved (dragged) positions stay where they are.
  function layout(nodes, saved) {
    const rank = n => (n.relay ? 0 : n.status === 'active' ? 1 : 2);
    const ordered = [...nodes].sort((a, b) => rank(a) - rank(b) || Number(a.id) - Number(b.id));
    const positions = {};
    const count = ordered.length, twoRings = count > 14;
    ordered.forEach((node, i) => {
      if (saved && saved[node.id]) { positions[node.id] = { x: saved[node.id].x, y: saved[node.id].y, pinned: true }; return; }
      if (count === 1) { positions[node.id] = { x: WIDTH / 2, y: HEIGHT / 2 - 20, pinned: false }; return; }
      const scale = twoRings && i % 2 ? 0.6 : 1;
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / count;
      positions[node.id] = { x: WIDTH / 2 + (WIDTH / 2 - 130) * scale * Math.cos(angle), y: HEIGHT / 2 - 12 + (HEIGHT / 2 - 85) * scale * Math.sin(angle), pinned: false };
    });
    return positions;
  }

  function speed(bytesPerSecond) {
    const bits = (Number(bytesPerSecond) || 0) * 8;
    if (bits >= 1e9) return (bits / 1e9).toFixed(1) + ' Gbit/s';
    if (bits >= 1e6) return (bits / 1e6).toFixed(1) + ' Mbit/s';
    if (bits >= 1e3) return Math.round(bits / 1e3) + ' kbit/s';
    return Math.round(bits) + ' bit/s';
  }

  class MeshMap {
    // svgElement: an <svg>; options.onSelect(nodeId | null); options.storage: a Storage or null.
    constructor(svgElement, options) {
      this.svg = svgElement;
      this.options = options || {};
      this.svg.setAttribute('viewBox', `0 0 ${WIDTH} ${HEIGHT}`);
      this.svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
      this.svg.classList.add('mesh-map');
      this.positions = {};
      this.layoutIds = null;
      this.selected = null;
      this.topology = null;
      this.drag = null;
      this.svg.addEventListener('pointermove', event => this.moveDrag(event));
      this.svg.addEventListener('pointerup', () => this.endDrag());
      this.svg.addEventListener('pointerleave', () => this.endDrag());
      // Pressing the background clears the selection (node presses don't reach the background).
      this.svg.addEventListener('pointerdown', event => { if (event.target === this.svg) this.select(null); });
    }

    storageKey() { return this.topology ? 'ghostlink-mesh-layout:' + this.topology.id : null; }

    saved() {
      try {
        const key = this.storageKey(), storage = this.options.storage;
        return key && storage ? JSON.parse(storage.getItem(key) || '{}') : {};
      } catch { return {}; }
    }

    save() {
      const key = this.storageKey(), storage = this.options.storage;
      if (!key || !storage) return;
      const out = {};
      for (const [id, p] of Object.entries(this.positions)) if (p.pinned) out[id] = { x: Math.round(p.x), y: Math.round(p.y) };
      try { storage.setItem(key, JSON.stringify(out)); } catch { /* storage full or off */ }
    }

    // forgetLayout drops dragged positions and lays the mesh out again.
    forgetLayout() {
      const key = this.storageKey();
      if (key && this.options.storage) this.options.storage.removeItem(key);
      this.positions = {};
      this.layoutIds = null;
      if (this.topology) this.update(this.topology);
    }

    update(topology) {
      if (this.topology && this.topology.id !== topology.id) { this.positions = {}; this.layoutIds = null; this.selected = null; }
      this.topology = topology;
      const nodes = topology.nodes || [];
      const ids = nodes.map(n => n.id).sort().join(',');
      // Lay out again only when nodes come or go; dragged nodes keep their place.
      if (ids !== this.layoutIds) {
        this.layoutIds = ids;
        const saved = this.saved();
        for (const [id, p] of Object.entries(this.positions)) if (p.pinned) saved[id] = p;
        this.positions = layout(nodes, saved);
      }
      this.render();
    }

    select(id) {
      this.selected = id;
      this.render();
      if (this.options.onSelect) this.options.onSelect(id);
    }

    render() {
      const t = this.topology;
      this.svg.replaceChildren();
      if (!t || !(t.nodes || []).length) {
        svg('text', { x: WIDTH / 2, y: HEIGHT / 2, 'text-anchor': 'middle', class: 'empty' }, this.svg).textContent = 'No nodes yet. Add one to see the map.';
        return;
      }
      const byId = {};
      for (const n of t.nodes) byId[n.id] = n;
      const linksLayer = svg('g', { class: 'links' }, this.svg);
      const routesLayer = svg('g', { class: 'routes' }, this.svg);
      const nodesLayer = svg('g', { class: 'nodes' }, this.svg);
      // Latency labels: on every link of a small mesh, else only on the selected node's links.
      const labelAll = (t.links || []).length <= 6;
      for (const link of t.links || []) {
        const a = this.positions[link.a], b = this.positions[link.b];
        if (!a || !b) continue;
        const busy = (link.rx_bps || 0) + (link.tx_bps || 0);
        const width = 2 + Math.min(5, Math.log10(1 + busy / 1000));
        const selected = this.selected && (link.a === this.selected || link.b === this.selected);
        const cls = `link ${link.path}${selected ? ' selected' : ''}`;
        // A relayed link bends through the relay, which is where its traffic goes.
        const r = link.path === 'relay' ? this.positions[link.via] : null;
        let line, mid;
        if (r) {
          // With this control point the curve passes through the relay at its middle.
          const cx = 2 * r.x - (a.x + b.x) / 2, cy = 2 * r.y - (a.y + b.y) / 2;
          line = svg('path', { d: `M ${a.x} ${a.y} Q ${cx} ${cy} ${b.x} ${b.y}`, class: cls, fill: 'none', 'stroke-width': width.toFixed(1) }, linksLayer);
          mid = { x: 0.5625 * a.x + 0.375 * cx + 0.0625 * b.x, y: 0.5625 * a.y + 0.375 * cy + 0.0625 * b.y }; // a quarter along
        } else {
          line = svg('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: cls, 'stroke-width': width.toFixed(1) }, linksLayer);
          mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
        }
        const via = link.path === 'relay' && byId[link.via] ? ` via ${byId[link.via].name}` : '';
        const rtt = link.rtt_ms > 0 ? `${link.rtt_ms.toFixed(1)} ms` : 'no ping yet';
        svg('title', {}, line).textContent = `${byId[link.a]?.name} ↔ ${byId[link.b]?.name}: ${link.path}${via}, ${rtt}, ${speed(busy)}`;
        if (link.rtt_ms > 0 && (labelAll || selected)) {
          const label = svg('text', { x: mid.x, y: mid.y - 4, 'text-anchor': 'middle', class: 'rtt' }, linksLayer);
          label.textContent = `${link.rtt_ms < 10 ? link.rtt_ms.toFixed(1) : Math.round(link.rtt_ms)} ms`;
        }
      }
      for (const node of t.nodes) {
        const p = this.positions[node.id];
        if (!p) continue;
        // Shared subnets: bubbles beside the node, on the side away from the middle.
        const routes = node.approved_routes || [];
        const right = p.x >= WIDTH / 2;
        routes.forEach((route, i) => {
          const w = route.length * 6.4 + 14;
          const ry = Math.min(HEIGHT - 22, Math.max(4, p.y - 9 + (i - (routes.length - 1) / 2) * 22));
          const rx = right ? Math.min(WIDTH - w - 4, p.x + RADIUS + 22) : Math.max(4, p.x - RADIUS - 22 - w);
          svg('line', { x1: p.x + (right ? RADIUS : -RADIUS), y1: p.y, x2: right ? rx : rx + w, y2: ry + 9, class: 'route-link' }, routesLayer);
          const box = svg('g', { class: 'route' }, routesLayer);
          svg('rect', { x: rx, y: ry, width: w, height: 18, rx: 9 }, box);
          svg('text', { x: rx + 7, y: ry + 13 }, box).textContent = route;
        });
        const state = node.status !== 'active' ? node.status : node.online ? 'online' : 'offline';
        const group = svg('g', { class: `node ${state}${node.id === this.selected ? ' selected' : ''}${node.relay_in_use ? ' relay' : ''}`, transform: `translate(${p.x} ${p.y})`, tabindex: 0, role: 'button' }, nodesLayer);
        // The relay in use has a dashed ring; a node sharing subnets is a rounded square.
        if (node.relay_in_use) svg('circle', { r: RADIUS + 6, class: 'relay-ring' }, group);
        if (routes.length) svg('rect', { x: -RADIUS, y: -RADIUS, width: 2 * RADIUS, height: 2 * RADIUS, rx: 9, class: 'shape' }, group);
        else svg('circle', { r: RADIUS, class: 'shape' }, group);
        svg('text', { y: 5, 'text-anchor': 'middle', class: 'glyph' }, group).textContent = node.name.slice(0, 1).toUpperCase();
        svg('text', { y: RADIUS + 16, 'text-anchor': 'middle', class: 'name' }, group).textContent = node.name;
        svg('text', { y: RADIUS + 29, 'text-anchor': 'middle', class: 'sub' }, group).textContent = node.status === 'pending' ? 'waiting for approval' : node.address;
        const tip = [`${node.name} (${node.address}) — ${state}`];
        if (node.relay_in_use) tip.push('relay for nodes that cannot connect directly');
        if ((node.tags || []).length) tip.push('tags: ' + node.tags.join(', '));
        if (node.error) tip.push('problem: ' + node.error);
        svg('title', {}, group).textContent = tip.join('\n');
        group.addEventListener('pointerdown', event => this.startDrag(event, node.id));
        group.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); this.select(node.id); } });
      }
    }

    point(event) {
      const box = this.svg.getBoundingClientRect();
      const scale = Math.min(box.width / WIDTH, box.height / HEIGHT) || 1;
      const offsetX = (box.width - WIDTH * scale) / 2, offsetY = (box.height - HEIGHT * scale) / 2;
      return { x: (event.clientX - box.left - offsetX) / scale, y: (event.clientY - box.top - offsetY) / scale };
    }

    startDrag(event, id) {
      event.preventDefault();
      const start = this.point(event);
      this.drag = { id, start, moved: false, origin: { ...this.positions[id] } };
      this.svg.setPointerCapture?.(event.pointerId);
    }

    moveDrag(event) {
      if (!this.drag) return;
      const now = this.point(event), d = this.drag;
      const dx = now.x - d.start.x, dy = now.y - d.start.y;
      if (!d.moved && Math.hypot(dx, dy) < 4) return;
      d.moved = true;
      this.positions[d.id] = { x: Math.min(WIDTH - 30, Math.max(30, d.origin.x + dx)), y: Math.min(HEIGHT - 45, Math.max(30, d.origin.y + dy)), pinned: true };
      this.render();
    }

    endDrag() {
      if (!this.drag) return;
      const d = this.drag;
      this.drag = null;
      if (d.moved) this.save();
      else this.select(d.id);
    }
  }

  global.GhostlinkMeshMap = { MeshMap, layout, speed, WIDTH, HEIGHT };
})(typeof window !== 'undefined' ? window : globalThis);
