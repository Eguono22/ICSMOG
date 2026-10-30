// Run with: node --test tests/dashboard.test.cjs
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('src/api/dashboard.py', 'utf8');
const functions = source.slice(source.indexOf('    let refreshSequence = 0;'), source.indexOf('    function render()'));

function workspace(fetchJson) {
  const nodes = new Map();
  const state = { filters: { threatLevel: '', status: '', sourceIp: 'old', destinationIp: '', protocol: '', query: 'old' } };
  const context = vm.createContext({
    dashboardState: state, fetchJson,
    document: { getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, { value: '', textContent: '' });
      return nodes.get(id);
    } },
    buildAlertEndpoint: () => '/alerts', buildAuthEndpoint: () => '/auth',
    render() {}, setStatus() {},
  });
  vm.runInContext(functions, context);
  return { context, state, nodes };
}

test('quick views reset previous filters and synchronize controls', async () => {
  const { context, state, nodes } = workspace(async () => ({}));
  await context.applyAlertView('critical');
  assert.equal(state.filters.status, 'open');
  assert.equal(state.filters.threatLevel, 'critical');
  assert.equal(state.filters.query, '');
  assert.equal(nodes.get('filter-source-ip').value, '');
  await context.applyAlertView('all');
  assert.ok(Object.values(state.filters).every(value => value === ''));
});

test('failed refresh preserves last successful data and reports staleness', async () => {
  let fail = false;
  const { context, state, nodes } = workspace(async () => {
    if (fail) throw new Error('Offline');
    return { alerts: [{ alert_id: 'saved' }] };
  });
  await context.refreshDashboard();
  const saved = state.alerts;
  fail = true;
  await context.refreshDashboard();
  assert.equal(state.alerts, saved);
  assert.match(nodes.get('refresh-status').textContent, /Offline.*out of date/);
});

test('late responses cannot overwrite the newest request', async () => {
  const pending = [];
  const { context, state } = workspace(() => new Promise(resolve => pending.push(resolve)));
  const first = context.refreshDashboard();
  const second = context.refreshDashboard();
  pending.slice(5).forEach(resolve => resolve({ alerts: [{ alert_id: 'new' }] }));
  await second;
  pending.slice(0, 5).forEach(resolve => resolve({ alerts: [{ alert_id: 'old' }] }));
  await first;
  assert.equal(state.alerts[0].alert_id, 'new');
});
