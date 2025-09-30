const path = require('path');
const express = require('express');
const app = express();
const fs = require('fs');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const multer = require('multer');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { fileTypeFromBuffer } = require('file-type');
const validator = require('validator');

// Cargar variables de entorno
require('dotenv').config();

// 🛡️ FUNCIÓN DE VALIDACIÓN DE VARIABLES DE ENTORNO MEJORADA
function validateEnvironment() {
  const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'SESSION_SECRET'];
  const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

  if (missingEnvVars.length > 0) {
    console.error('❌ Error: Variables de entorno faltantes:', missingEnvVars);
    console.error('📋 Crea un archivo .env con:');
    requiredEnvVars.forEach(varName => {
      console.error(`   ${varName}=tu_valor_aqui`);
    });
    process.exit(1);
  }
  
  console.log('✅ Variables de entorno validadas correctamente');
}

// Validar entorno al inicio
validateEnvironment();

const port = process.env.PORT || 3000;

// 🛡️ HEADERS DE SEGURIDAD
app.use((req, res, next) => {
  // Content Security Policy
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: https:; " +
    "connect-src 'self';"
  );
  
  // Otros headers de seguridad
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  next();
});

// Ocultar tecnología del servidor
app.disable('x-powered-by');

const uploadDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log('Carpeta uploads creada');
}

const usersPath = path.join(__dirname, 'users.json');
let users = [];

function loadUsers() {
  try {
    users = JSON.parse(fs.readFileSync(usersPath, 'utf-8'));
  } catch (err) {
    users = [];
    console.error('Error cargando usuarios:', err);
  }
}

function saveUsers() {
  try {
    fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
  } catch (err) {
    console.error('Error guardando usuarios:', err);
  }
}

loadUsers();
console.log('Usuarios cargados:', users.length, 'usuarios encontrados');

// 🛡️ FUNCIÓN DE SANITIZACIÓN DE INPUTS
function sanitizeInput(str) {
  if (!str) return '';
  return validator.escape(str.toString().trim());
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { 
    fileSize: 20 * 1024 * 1024, // 20 MB máx
    files: 1 
  },
});

// Tipos permitidos con tamaños específicos
const allowedMimeTypes = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'video/mp4',
  'video/webm',
  'video/ogg'
];

const maxSizes = {
  'image/jpeg': 5 * 1024 * 1024,   // 5MB
  'image/png': 5 * 1024 * 1024,    // 5MB
  'image/gif': 10 * 1024 * 1024,   // 10MB
  'video/mp4': 50 * 1024 * 1024,   // 50MB
  'video/webm': 50 * 1024 * 1024,  // 50MB
  'video/ogg': 50 * 1024 * 1024    // 50MB
};

// 🛡️ MIDDLEWARE PARA PROTEGER ARCHIVOS
function ensureAuthenticatedFile(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Acceso no autorizado a archivo' });
}

// 🛡️ RUTAS PROTEGIDAS PARA SERVIR ARCHIVOS
app.get('/secure-uploads/:filename', ensureAuthenticatedFile, (req, res) => {
  const filename = req.params.filename;
  
  // Validar que el nombre de archivo sea seguro
  if (!/^[a-zA-Z0-9\-_.]+$/.test(filename)) {
    return res.status(400).json({ error: 'Nombre de archivo inválido' });
  }
  
  const filePath = path.join(uploadDir, filename);
  
  // Verificar que el archivo existe y está dentro de uploadDir
  if (!fs.existsSync(filePath) || !filePath.startsWith(uploadDir)) {
    return res.status(404).json({ error: 'Archivo no encontrado' });
  }
  
  // Log del acceso para auditoría
  console.log(`Usuario ${req.user.username} accedió a archivo: ${filename}`);
  
  // Servir el archivo
  res.sendFile(filePath);
});

// Ruta para directores que puedan ver cualquier archivo
app.get('/admin-uploads/:filename', ensureDirector, (req, res) => {
  const filename = req.params.filename;
  
  if (!/^[a-zA-Z0-9\-_.]+$/.test(filename)) {
    return res.status(400).json({ error: 'Nombre de archivo inválido' });
  }
  
  const filePath = path.join(uploadDir, filename);
  
  if (!fs.existsSync(filePath) || !filePath.startsWith(uploadDir)) {
    return res.status(404).json({ error: 'Archivo no encontrado' });
  }
  
  console.log(`Director ${req.user.username} accedió a archivo: ${filename}`);
  res.sendFile(filePath);
});

// 🛡️ ENDPOINT DE UPLOAD MEJORADO CON SEGURIDAD
app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No se envió archivo' });
    }

    // Detectar tipo real del archivo
    const detected = await fileTypeFromBuffer(req.file.buffer);
    if (!detected || !allowedMimeTypes.includes(detected.mime)) {
      return res.status(400).json({ error: 'Tipo de archivo no permitido' });
    }

    // Validar tamaño específico por tipo
    if (req.file.buffer.length > (maxSizes[detected.mime] || 1024 * 1024)) {
      return res.status(400).json({ error: 'Archivo demasiado grande para este tipo' });
    }

    // Nombre ultra-seguro con UUID
    const safeName = `${Date.now()}-${crypto.randomUUID()}.${detected.ext}`;
    
    // Organizar por fecha para mejor estructura
    const dateFolder = new Date().toISOString().split('T')[0];
    const uploadPath = path.join(uploadDir, dateFolder);
    
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    
    const savePath = path.join(uploadPath, safeName);

    // Guardar en disco solo si pasó todas las validaciones
    fs.writeFileSync(savePath, req.file.buffer);

    res.json({ success: true, file: `/secure-uploads/${dateFolder}/${safeName}` });
  } catch (err) {
    console.error('Error en upload:', err);
    res.status(500).json({ error: 'Error al subir archivo' });
  }
});

// Configuración segura de la base de datos usando variables de entorno
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: parseInt(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  // Configuraciones adicionales de seguridad
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
};

// Crear pool de conexiones con manejo de errores
let pool;
try {
  pool = mysql.createPool(dbConfig);
  console.log('Pool de conexiones de base de datos creado exitosamente');
} catch (error) {
  console.error('Error creando pool de base de datos:', error);
  process.exit(1);
}

// Función para probar la conexión a la base de datos
async function testDatabaseConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('Conexión a base de datos establecida exitosamente');
    connection.release();
    return true;
  } catch (error) {
    console.error('Error conectando a la base de datos:', error);
    return false;
  }
}

// Probar conexión al iniciar la aplicación
testDatabaseConnection();

// Función helper para ejecutar queries con mejor manejo de errores
async function executeQuery(sql, params = []) {
  try {
    const [results] = await pool.execute(sql, params);
    return results;
  } catch (error) {
    console.error('Error ejecutando query:', error);
    throw error;
  }
}

// Configuración segura de sesiones
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // Cambiar nombre por defecto
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS en producción
    httpOnly: true, // Prevenir acceso desde JavaScript
    maxAge: 24 * 60 * 60 * 1000, // 24 horas
    sameSite: 'strict' // Protección CSRF
  }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
  async (username, password, done) => {
    loadUsers();
    const user = users.find(u => u.username === username);
    if (!user) return done(null, false);

    try {
      if (user.password.startsWith('$2')) {
        const match = await bcrypt.compare(password, user.password);
        return match ? done(null, user) : done(null, false);
      } else {
        if (password === user.password) {
          const hashed = await bcrypt.hash(password, 10);
          user.password = hashed;
          saveUsers();
          return done(null, user);
        } else {
          return done(null, false);
        }
      }
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  loadUsers();
  const user = users.find(u => u.id === parseInt(id) || u.id === id);
  done(null, user || false);
});

function ensureDirector(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'director') {
    return next();
  }
  res.status(403).send('Acceso denegado');
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).send('No autorizado');
}

app.get('/api/users', ensureDirector, (req, res) => {
  loadUsers();
  const staffs = users.filter(u => u.role !== 'director');
  res.json(staffs);
});

app.post('/api/users', ensureDirector, async (req, res) => {
  loadUsers();
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }
  if (users.find(u => u.username === username)) {
    return res.status(409).json({ error: 'El nombre de usuario ya existe' });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    const newUser = {
      id: Date.now(),
      username,
      password: hashed,
      role
    };
    users.push(newUser);
    saveUsers();
    res.status(201).json({ id: newUser.id, username: newUser.username, role: newUser.role });
  } catch (err) {
    console.error('Error guardando usuario:', err);
    res.status(500).json({ error: 'Error al guardar usuario' });
  }
});

// Endpoint para eliminar un usuario
app.delete('/api/users/:id', ensureDirector, (req, res) => {
  loadUsers();
  const userId = req.params.id;
  
  // Convertir a número si es posible (para manejar IDs numéricos)
  const idToFind = isNaN(userId) ? userId : parseInt(userId);
  
  // Verificar si el usuario existe
  const userIndex = users.findIndex(u => u.id === idToFind);
  
  if (userIndex === -1) {
    return res.status(404).json({ error: 'Usuario no encontrado' });
  }
  
  // Comprobar que no se está intentando eliminar un director
  if (users[userIndex].role === 'director') {
    return res.status(403).json({ error: 'No se puede eliminar a un director' });
  }
  
  // Eliminar el usuario
  users.splice(userIndex, 1);
  saveUsers();
  
  res.json({ success: true, message: 'Usuario eliminado correctamente' });
});

// Endpoint para actualizar un usuario (cambiar rol)
app.patch('/api/users/:id', ensureDirector, async (req, res) => {
  loadUsers();
  const userId = req.params.id;
  const { role } = req.body;
  
  // Verificar que se proporciona un rol
  if (!role) {
    return res.status(400).json({ error: 'Se debe proporcionar un rol' });
  }
  
  // Convertir a número si es posible (para manejar IDs numéricos)
  const idToFind = isNaN(userId) ? userId : parseInt(userId);
  
  // Verificar si el usuario existe
  const userIndex = users.findIndex(u => u.id === idToFind);
  
  if (userIndex === -1) {
    return res.status(404).json({ error: 'Usuario no encontrado' });
  }
  
  // Actualizar el rol del usuario
  users[userIndex].role = role;
  saveUsers();
  
  res.json({ 
    success: true, 
    message: 'Usuario actualizado correctamente',
    user: {
      id: users[userIndex].id,
      username: users[userIndex].username,
      role: users[userIndex].role
    }
  });
});

// Función para convertir dd-mm-yyyy a yyyy-mm-dd
function convertDateFormat(dateStr) {
  if (!dateStr) return null;
  const parts = dateStr.split('-');
  if (parts.length !== 3) return null;
  return `${parts[2]}-${parts[1].padStart(2,'0')}-${parts[0].padStart(2,'0')}`;
}

app.get('/adminpanel/activities', ensureDirector, async (req, res) => {
  const { role, staff, startDate, endDate } = req.query;

  try {
    let sql = 'SELECT id, staff, role, user, activityType, reason, proof, date FROM activities WHERE 1=1';
    const params = [];

    if (role) {
      sql += ' AND role = ?';
      params.push(role);
    }
    if (staff) {
      sql += ' AND staff = ?';
      params.push(staff);
    }

    const start = convertDateFormat(startDate);
    const end = convertDateFormat(endDate);

    if (start) {
      sql += ' AND date >= ?';
      params.push(start);
    }
    if (end) {
      sql += ' AND date <= ?';
      params.push(end + ' 23:59:59');
    }

    sql += ' ORDER BY date DESC';

    const rows = await executeQuery(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al obtener actividades');
  }
});

app.get('/current-user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ username: req.user.username, role: req.user.role });
  } else {
    res.status(401).json({ error: 'No autenticado' });
  }
});

app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.redirect('/login?error=1');
    req.logIn(user, (err) => {
      if (err) return next(err);
      if (user.role === 'director') {
        return res.redirect('/adminpanel');
      } else {
        return res.redirect('/dashboard');
      }
    });
  })(req, res, next);
});

app.post('/logout', (req, res, next) => {
  req.logout(function(err) {
    if (err) {
      console.error('Error al cerrar sesión:', err);
      return next(err);
    }
    req.session.destroy((err) => {
      if (err) {
        console.error('Error al destruir sesión:', err);
        return res.status(500).json({ error: 'Error al cerrar sesión' });
      }
      res.clearCookie('connect.sid');
      res.json({ success: true, redirect: '/login' });
    });
  });
});

// 🛡️ ENDPOINT MEJORADO PARA REGISTRAR ACTIVIDAD CON SANITIZACIÓN
app.post('/register-activity', ensureAuthenticated, upload.single('media'), async (req, res) => {
  const { activityType, user, reason, proofLink } = req.body;
  let proofPath = null;
  
  // Si hay archivo, procesarlo y guardarlo
  if (req.file) {
    try {
      // Detectar tipo real
      const detected = await fileTypeFromBuffer(req.file.buffer);
      if (!detected || !allowedMimeTypes.includes(detected.mime)) {
        return res.status(400).json({ error: 'Tipo de archivo no permitido' });
      }

      // Validar tamaño específico
      if (req.file.buffer.length > (maxSizes[detected.mime] || 1024 * 1024)) {
        return res.status(400).json({ error: 'Archivo demasiado grande para este tipo' });
      }

      // Nombre seguro + extensión correcta
      const safeName = `${Date.now()}-${crypto.randomUUID()}.${detected.ext}`;
      const savePath = path.join(uploadDir, safeName);

      // Guardar en disco
      fs.writeFileSync(savePath, req.file.buffer);
      proofPath = safeName; // Solo el nombre del archivo
    } catch (error) {
      console.error('Error procesando archivo:', error);
      return res.status(500).json({ error: 'Error al procesar archivo' });
    }
  }
  
  // 🛡️ SANITIZAR TODOS LOS INPUTS
  const sanitizedData = {
    activityType: sanitizeInput(activityType),
    user: sanitizeInput(user),
    reason: sanitizeInput(reason),
    proof: proofPath || (proofLink && validator.isURL(proofLink) ? proofLink : null)
  };

  if (!sanitizedData.activityType || !sanitizedData.user || !sanitizedData.reason || !sanitizedData.proof) {
    return res.status(400).send('Faltan campos obligatorios');
  }
  
  try {
    const sql = `INSERT INTO activities (staff, role, user, activityType, reason, proof, date)
                  VALUES (?, ?, ?, ?, ?, ?, ?)`;
    const params = [
      req.user.username,
      req.user.role,
      sanitizedData.user,
      sanitizedData.activityType,
      sanitizedData.reason,
      sanitizedData.proof,
      new Date()
    ];
    await executeQuery(sql, params);
    res.redirect('/dashboard?success=1');
  } catch (err) {
    console.error('Error al registrar actividad:', err);
    res.status(500).send('Error al registrar actividad');
  }
});

app.get('/activities', ensureAuthenticated, async (req, res) => {
  try {
    const sql = 'SELECT * FROM activities WHERE staff = ? ORDER BY date DESC';
    const rows = await executeQuery(sql, [req.user.username]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al obtener actividades');
  }
});

app.post('/change-password', ensureAuthenticated, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  const passwordRegex = /^(?=.*\d)(?=.*[!@#$%^&*])[\S]{8,16}$/;
  if (!passwordRegex.test(newPassword)) {
    return res.status(400).json({
      error: 'La contraseña debe tener entre 8 y 16 caracteres, incluir al menos un número y un carácter especial, y no contener espacios.'
    });
  }

  loadUsers();
  const userIndex = users.findIndex(u => u.id === req.user.id);
  if (userIndex === -1) {
    return res.status(404).json({ error: 'Usuario no encontrado' });
  }

  const user = users[userIndex];

  const match = await bcrypt.compare(currentPassword, user.password);
  if (!match) {
    return res.status(400).json({ error: 'La contraseña actual es incorrecta' });
  }

  user.password = await bcrypt.hash(newPassword, 10);
  saveUsers();

  res.json({ message: 'Contraseña actualizada correctamente' });
});

app.use(express.static(path.join(__dirname, '../frontend/public')));

// Middleware para remover extensión .html de las URLs
app.use((req, res, next) => {
  if (req.path.endsWith('.html')) {
    const newPath = req.path.slice(0, -5);
    return res.redirect(301, newPath);
  }
  
  const htmlPath = path.join(__dirname, '../frontend/public', req.path + '.html');
  
  fs.access(htmlPath, fs.constants.F_OK, (err) => {
    if (!err) {
      res.sendFile(htmlPath);
    } else {
      next();
    }
  });
});

// 🛡️ MIDDLEWARE DE MANEJO DE ERRORES MEJORADO
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  // No mostrar stack traces en producción
  if (process.env.NODE_ENV === 'production') {
    res.status(500).send('Error interno del servidor');
  } else {
    res.status(500).send(`Error interno del servidor: ${err.message}`);
  }
});

// Función para cerrar el pool de conexiones cuando la app se cierre
process.on('SIGINT', async () => {
  console.log('Cerrando pool de conexiones de base de datos...');
  if (pool) {
    await pool.end();
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Cerrando pool de conexiones de base de datos...');
  if (pool) {
    await pool.end();
  }
  process.exit(0);
});

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
  console.log(`Entorno: ${process.env.NODE_ENV || 'development'}`);
});