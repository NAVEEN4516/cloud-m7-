/** Local Review 2 server. Each dataset owns its own persisted evidence and SQL view. */
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const app = express();
const PORT = process.env.PORT || 3001;
const ROOT = path.resolve(__dirname, '..');
const UPLOADS = path.join(__dirname, 'uploads');
const python = process.env.CLOUD_M7_PYTHON || path.join(ROOT, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
fs.mkdirSync(UPLOADS, { recursive: true });
const cache = new Map();
const upload = multer({ dest: UPLOADS, limits: { fileSize: 5 * 1024 * 1024, files: 1 } });
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/vendor/vis-network.min.js', (req, res) => res.sendFile(path.join(__dirname, 'node_modules/vis-network/standalone/umd/vis-network.min.js')));
app.get('/vendor/vis-network.LICENSE', (req, res) => res.sendFile(path.join(__dirname, 'node_modules/vis-network/LICENSE-MIT')));
function bridge(args) {
  return new Promise((resolve, reject) => {
    const py = spawn(python, ['-m', 'cloud_m7.bridge_api', ...args], {
      cwd: ROOT, env: { ...process.env, PYTHONPATH: ROOT, PYTHONIOENCODING: 'utf-8' }, windowsHide: true
    });
    let output = '', errors = '', settled = false;
    const timer = setTimeout(() => { py.kill(); reject(new Error('Analysis timed out after 60 seconds')); }, 60000);
    py.stdout.on('data', x => { output += x; if (output.length > 25000000) py.kill(); });
    py.stderr.on('data', x => { errors = (errors + x).slice(-4000); });
    py.on('error', e => { clearTimeout(timer); settled = true; reject(new Error(`Python could not start. Run setup_demo.ps1. ${e.message}`)); });
    py.on('close', code => {
      clearTimeout(timer);
      if (settled) return;
      if (code !== 0) return reject(new Error(errors || `Analysis exited with code ${code}`));
      try { resolve(JSON.parse(output)); } catch { reject(new Error(`Invalid analysis response. ${errors}`)); }
    });
  });
}
const reply = (res, data) => res.status(data.status === 'error' ? 400 : 200).json(data);
app.get('/api/health', (req, res) => res.json({ status: 'online', version: 'review2', python, port: PORT }));
app.get('/api/datasets', (req, res) => res.json({ datasets: [
  { id: 'attack', label: 'Three-source attack', description: '70 events / 3 edge sources / controlled ground truth' },
  { id: 'repeated', label: 'Attack + repeated reads', description: '92 events / evidence-preserving reduction' },
  { id: 'normal', label: 'Normal activity', description: '16 events / no attack labels' }
] }));
app.get('/api/analyze', async (req, res, next) => {
  const dataset = String(req.query.dataset || 'repeated');
  if (!['attack','repeated','normal','synthetic','darpa_optc','darpa_tc','ton_iot','iot23'].includes(dataset) && !/^ds-[a-f0-9]{64}$/.test(dataset))
    return reply(res, { status: 'error', message: 'Unknown dataset selection' });
  try {
    if (req.query.force !== 'true' && cache.has(dataset)) return res.json({ ...cache.get(dataset), from_cache: true });
    const data = await bridge(['--action','analyze','--dataset',dataset]);
    if (data.status !== 'error') { cache.set(dataset, data); cache.set(data.dataset_id, data); }
    reply(res, data);
  } catch (e) { next(e); }
});
app.post('/api/upload', upload.single('dataset_file'), async (req, res, next) => {
  if (!req.file) return reply(res, { status: 'error', message: 'Select a JSON or CSV file first' });
  // Multer temp names have no suffix. Keep the original format explicit and always clean up.
  const file = path.join(UPLOADS, path.basename(req.file.filename) + path.extname(req.file.originalname).toLowerCase());
  try {
    if (!/\.(json|jsonl|csv|tsv|log)$/i.test(req.file.originalname)) throw new Error('Unsupported file extension');
    fs.renameSync(req.file.path, file);
    const data = await bridge(['--action','analyze','--dataset',file]);
    if (data.status !== 'error') {
      data.dataset_name = req.file.originalname;
      data.dataset_provenance.source = req.file.originalname;
      cache.set(data.dataset_id, data);
    }
    reply(res, data);
  } catch (e) { next(e); }
  finally { for (const name of [file,req.file.path]) if (fs.existsSync(name)) fs.unlinkSync(name); }
});
app.post('/api/sql', async (req, res, next) => {
  if (typeof req.body.query !== 'string' || !req.body.query.trim()) return reply(res, { status: 'error', message: 'Enter a SELECT query' });
  try { reply(res, await bridge(['--action','sql','--dataset-id',String(req.body.dataset_id || ''),'--query',req.body.query])); }
  catch (e) { next(e); }
});
app.post('/api/hardware/trigger', (req, res) => reply(res, { status: 'error', message: 'Hardware capture is outside this controlled laptop demonstration.' }));
app.use((err, req, res, next) => {
  console.error(`${req.method} ${req.path}: ${err.message}`);
  res.status(400).json({ status: 'error', message: err.message });
});
if (require.main === module) app.listen(PORT, '127.0.0.1', () => console.log(`CLOUD-M7 Review 2 ready at http://localhost:${PORT}`));
module.exports = app;
