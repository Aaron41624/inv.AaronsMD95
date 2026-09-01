const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const Loki = require('lokijs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'clave_secreta_para_administracion';

app.use(bodyParser.json());
app.use(express.static(path.join(process.cwd(), 'public')));

// Base de datos local LokiJS (Guardado en sistema.json)
let dbUsuarios, dbProductos, dbTransacciones;

const db = new Loki(path.join(process.cwd(), 'sistema.json'), {
  autoload: true,
  autoloadCallback: databaseInitialize,
  autosave: true,
  autosaveInterval: 4000
});

function databaseInitialize() {
  dbUsuarios = db.getCollection('usuarios') || db.addCollection('usuarios');
  dbProductos = db.getCollection('productos') || db.addCollection('productos');
  dbTransacciones = db.getCollection('transacciones') || db.addCollection('transacciones');

  const admin = dbUsuarios.findOne({ usuario: 'admin' });
  if (!admin) {
    dbUsuarios.insert({ id: 1, usuario: 'admin', password: 'admin123', rol: 'administrador' });
    console.log('Usuario admin listo (admin / admin123)');
  }
  
  console.log('Base de datos local iniciada correctamente en sistema.json');
}

app.get('/', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
});

// Login
app.post('/api/login', async (req, res) => {
  const { usuario, password } = req.body;
  const user = dbUsuarios.findOne({ usuario });

  if (!user) return res.status(400).json({ error: 'Usuario incorrecto' });

  let esValido = (usuario === 'admin' && password === 'admin123') || await bcrypt.compare(password, user.password);
  if (!esValido) return res.status(400).json({ error: 'Contraseña incorrecta' });

  const token = jwt.sign({ id: user.$loki, usuario: user.usuario, rol: user.rol }, SECRET_KEY, { expiresIn: '8h' });
  res.json({ status: 'success', token, usuario: user.usuario, rol: user.rol });
});

// Middleware Autenticación Token
function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Acceso denegado' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
}

// Obtener Productos
app.get('/api/productos', autenticarToken, (req, res) => {
  const productos = dbProductos.find().map(p => ({ ...p, id: p.$loki }));
  res.json({ status: 'success', data: productos });
});

// Crear Producto
app.post('/api/productos', autenticarToken, (req, res) => {
  const { nombre, precioVenta, precioCosto, existencia, almacen } = req.body;
  const nuevo = dbProductos.insert({
    nombre,
    precioVenta: parseFloat(precioVenta) || 0,
    precioCosto: parseFloat(precioCosto) || 0,
    existencia: parseInt(existencia) || 0,
    almacen: almacen || 'Almacen Central'
  });
  res.status(201).json({ status: 'success', id: nuevo.$loki });
});

// Ventas
app.post('/api/ventas', autenticarToken, (req, res) => {
  const { productoId, cantidad, cliente } = req.body;
  const prod = dbProductos.get(productoId);

  if (!prod || prod.existencia < cantidad) {
    return res.status(400).json({ error: 'Stock insuficiente' });
  }

  prod.existencia -= cantidad;
  dbProductos.update(prod);

  dbTransacciones.insert({
    tipo: 'VENTA',
    concepto: `Venta a ${cliente || 'Cliente'} - ${prod.nombre}`,
    monto: prod.precioVenta * cantidad,
    cantidad,
    fecha: new Date()
  });

  res.status(201).json({ status: 'success' });
});

// Compras
app.post('/api/compras', autenticarToken, (req, res) => {
  const { productoId, cantidad, proveedor } = req.body;
  const prod = dbProductos.get(productoId);

  if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });

  prod.existencia += cantidad;
  dbProductos.update(prod);

  dbTransacciones.insert({
    tipo: 'COMPRA',
    concepto: `Compra a ${proveedor || 'Proveedor'} - ${prod.nombre}`,
    monto: prod.precioCosto * cantidad,
    cantidad,
    fecha: new Date()
  });

  res.status(201).json({ status: 'success' });
});

// Balance Finanzas
app.get('/api/finanzas/balance', autenticarToken, (req, res) => {
  const ventas = dbTransacciones.find({ tipo: 'VENTA' }).reduce((sum, t) => sum + t.monto, 0);
  const egresos = dbTransacciones.find({ tipo: 'COMPRA' }).reduce((sum, t) => sum + t.monto, 0);

  res.json({
    status: 'success',
    resumen: {
      totalIngresos: ventas,
      totalEgresos: egresos,
      balanceNeto: ventas - egresos
    }
  });
});

// Usuarios
app.get('/api/usuarios', autenticarToken, (req, res) => {
  if (req.user.rol !== 'administrador') return res.status(403).json({ error: 'Acceso denegado' });
  const usuarios = dbUsuarios.find().map(u => ({ id: u.$loki, usuario: u.usuario, rol: u.rol }));
  res.json({ status: 'success', data: usuarios });
});

app.post('/api/usuarios', autenticarToken, async (req, res) => {
  if (req.user.rol !== 'administrador') return res.status(403).json({ error: 'Acceso denegado' });
  const { usuario, password, rol } = req.body;

  if (dbUsuarios.findOne({ usuario })) return res.status(400).json({ error: 'El usuario ya existe' });

  const hashPassword = await bcrypt.hash(password, 10);
  const nuevo = dbUsuarios.insert({ usuario, password: hashPassword, rol: rol || 'vendedor' });
  res.status(201).json({ status: 'success', id: nuevo.$loki });
});

// Iniciar NW.js si está presente
if (typeof nw !== 'undefined') {
  nw.Window.open('http://localhost:3000', { width: 1024, height: 700 });
}

app.listen(PORT, () => console.log(`Servidor ejecutándose en http://localhost:${PORT}`));