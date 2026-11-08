import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const projectRoot = path.resolve(import.meta.dirname, '..');
const distDir = path.join(projectRoot, 'dist');

console.log('[Build] 1/3 Compilando CSS Tailwind para producción...');
const tailwindBin = '/home/kevindarnet/.gemini/antigravity/scratch/academic-dashboard-os/node_modules/.bin/tailwindcss';
execFileSync(
  tailwindBin,
  [
    '-c', path.join(projectRoot, 'tailwind.config.js'),
    '-i', path.join(projectRoot, 'src/styles/main.css'),
    '-o', path.join(projectRoot, 'styles/app.css'),
    '--minify'
  ],
  { stdio: 'inherit' }
);

console.log('[Build] 2/3 Preparando directorio dist/...');
fs.rmSync(distDir, { recursive: true, force: true });
fs.mkdirSync(distDir, { recursive: true });

function copyDirRecursive(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirRecursive(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// Copiar archivos estáticos clave a dist
fs.copyFileSync(path.join(projectRoot, 'index.html'), path.join(distDir, 'index.html'));
copyDirRecursive(path.join(projectRoot, 'src'), path.join(distDir, 'src'));
copyDirRecursive(path.join(projectRoot, 'styles'), path.join(distDir, 'styles'));

console.log('[Build] 3/3 Verificando assets y estructura en dist/...');
const distFiles = [
  path.join(distDir, 'index.html'),
  path.join(distDir, 'src/main.js'),
  path.join(distDir, 'styles/app.css')
];

for (const file of distFiles) {
  if (!fs.existsSync(file)) {
    throw new Error(`Asset requerido no encontrado en build: ${file}`);
  }
}

console.log('[Build] ✓ Build finalizado con éxito en dist/. Listo para despliegue en Firebase Hosting.');
