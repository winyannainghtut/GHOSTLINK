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

  // A small deterministic pseudo-random generator, so the same mesh always lays out the same.
  function seeded(text) {
    let h = 2166136261;
    for (const ch of text) h = Math.imul(h ^ ch.charCodeAt(0), 16777619);
    return () => {
      h = Math.imul(h ^ (h >>> 15), 2246822507);
      h = Math.imul(h ^ (h >>> 13), 3266489909);
      return ((h ^= h >>> 16) >>> 0) / 4294967296;
    };
  }

  // Force-directed placement (Fruchterman-Reingold). Saved positions stay where they are.
  function layout(nodes, links, saved) {
    const positions = {};
    const ids = nodes.map(n => n.id).sort((a, b) => Number(a) - Number(b));
    const random = seeded(ids.join(','));
    ids.forEach((id, i) => {
      if (saved && saved[id]) positions[id] = { x: saved[id].x, y: saved[id].y, pinned: true };
      else {
        const angle = (2 * Math.PI * i) / Math.max(ids.length, 1);
        positions[id] = { x: WIDTH / 2 + 170 * Math.cos(angle) + random() * 20, y: HEIGHT / 2 + 150 * Math.sin(angle) + random() * 20, pinned: false };
      }
    });
    const free = ids.filter(id => !positions[id].pinned);
    if (free.length) {
      const k = Math.sqrt((WIDTH * HEIGHT) / Math.max(ids.length, 1)) * 0.7;
      let temperature = 60;
      for (let step = 0; step < 220; step++) {
        const shift = {};
        for (const id of ids) shift[id] = { x: 0, y: 0 };
        for (let i = 0; i < ids.length; i++) {
          for (let j = i + 1; j < ids.length; j++) {
            const a = positions[ids[i]], b = positions[ids[j]];
            let dx = a.x - b.x, dy = a.y - b.y;
            const distance = Math.max(Math.hypot(dx, dy), 0.01);
            const force = (k * k) / distance;
            dx /= distance; dy /= distance;
            shift[ids[i]].x += dx * force; shift[ids[i]].y += dy * force;
            shift[ids[j]].x -= dx * force; shift[ids[j]].y -= dy * force;
          }
        }
        for (const link of links) {
          const a = positions[link.a], b = positions[link.b];
          if (!a || !b) continue;
          let dx = a.x - b.x, dy = a.y - b.y;
          const distance = Math.max(Math.hypot(dx, dy), 0.01);
          const force = (distance * distance) / k;
          dx /= distance; dy /= distance;
          shift[link.a].x -= dx * force; shift[link.a].y -= dy * force;
          shift[link.b].x += dx * force; shift[link.b].y += dy * force;
        }
        for (const id of free) {
          const s = shift[id], length = Math.max(Math.hypot(s.x, s.y), 0.01);
          const p = positions[id];
          p.x = Math.min(WIDTH - 70, Math.max(70, p.x + (s.x / length) * Math.min(length, temperature)));
          p.y = Math.min(HEIGHT - 70, Math.max(50, p.y + (s.y / length) * Math.min(length, temperature)));
        }
        temperature *= 0.97;
      }
    }
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
      if (this.topology) this.update(this.topology);
    }

    update(topology) {
      if (this.topology && this.topology.id !== topology.id) { this.positions = {}; this.selected = null; }
      this.topology = topology;
      const nodes = topology.nodes || [];
      const missing = nodes.some(n => !this.positions[n.id]);
      if (missing) {
        const saved = this.saved();
        for (const [id, p] of Object.entries(this.positions)) if (p.pinned) saved[id] = p;
        const placed = layout(nodes, topology.links || [], saved);
        for (const n of nodes) if (!this.positions[n.id]) this.positions[n.id] = placed[n.id];
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
      for (const link of t.links || []) {
        const a = this.positions[link.a], b = this.positions[link.b];
        if (!a || !b) continue;
        const busy = (link.rx_bps || 0) + (link.tx_bps || 0);
        const width = 2 + Math.min(5, Math.log10(1 + busy / 1000));
        const selected = this.selected && (link.a === this.selected || link.b === this.selected);
        const line = svg('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: `link ${link.path}${selected ? ' selected' : ''}`, 'stroke-width': width.toFixed(1) }, linksLayer);
        const via = link.path === 'relay' && byId[link.via] ? ` via ${byId[link.via].name}` : '';
        const rtt = link.rtt_ms > 0 ? `${link.rtt_ms.toFixed(1)} ms` : 'no ping yet';
        svg('title', {}, line).textContent = `${byId[link.a]?.name} ↔ ${byId[link.b]?.name}: ${link.path}${via}, ${rtt}, ${speed(busy)}`;
        if (link.rtt_ms > 0) {
          const label = svg('text', { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - 4, 'text-anchor': 'middle', class: 'rtt' }, linksLayer);
          label.textContent = `${link.rtt_ms < 10 ? link.rtt_ms.toFixed(1) : Math.round(link.rtt_ms)} ms`;
        }
      }
      for (const node of t.nodes) {
        const p = this.positions[node.id];
        if (!p) continue;
        (node.approved_routes || []).forEach((route, i) => {
          const rx = p.x + 52, ry = p.y - 28 + i * 22;
          svg('line', { x1: p.x + RADIUS - 4, y1: p.y, x2: rx, y2: ry + 9, class: 'route-link' }, routesLayer);
          const box = svg('g', { class: 'route' }, routesLayer);
          svg('rect', { x: rx, y: ry, width: route.length * 6.4 + 14, height: 18, rx: 9 }, box);
          svg('text', { x: rx + 7, y: ry + 13 }, box).textContent = route;
        });
        const state = node.status !== 'active' ? node.status : node.online ? 'online' : 'offline';
        const group = svg('g', { class: `node ${state}${node.id === this.selected ? ' selected' : ''}${node.relay_in_use ? ' relay' : ''}`, transform: `translate(${p.x} ${p.y})`, tabindex: 0, role: 'button' }, nodesLayer);
        if (node.relay_in_use) svg('circle', { r: RADIUS + 6, class: 'relay-ring' }, group);
        svg('circle', { r: RADIUS }, group);
        svg('text', { y: 4, 'text-anchor': 'middle', class: 'glyph' }, group).textContent = node.relay_in_use ? 'R' : (node.approved_routes || []).length ? 'S' : node.name.slice(0, 1).toUpperCase();
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
