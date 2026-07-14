const { app, BrowserWindow, ipcMain, dialog, Menu, Tray } = require('electron');
const path = require('path');
const fs = require('fs');

let mainWindow = null;
let tray = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 600,
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: false
    },
    frame: false,
    show: false
  });

  mainWindow.loadFile('index.html');

  // 外部链接在默认浏览器打开
  mainWindow.webContents.setWindowOpenHandler(function (details) {
    if (details.url && details.url.startsWith('http')) {
      require('electron').shell.openExternal(details.url);
      return { action: 'deny' };
    }
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', function (e, url) {
    if (url.startsWith('http')) {
      e.preventDefault();
      require('electron').shell.openExternal(url);
    }
  });
  

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    // 检查命令行参数是否有日志文件
    const fileArg = getFileFromArgv();
    if (fileArg) {
      sendFileToRenderer(fileArg);
    }
  });

  // 窗口关闭拦截（保存位置 + 退出确认）
  mainWindow.on('close', function (e) {
    if (app.isQuitting) return;
    e.preventDefault();
    try {
      const bounds = mainWindow.getBounds();
      fs.writeFileSync(getStatePath(), JSON.stringify(bounds));
    } catch (_) {}
    mainWindow.webContents.send('app:confirm-quit');
  });
}

// 文件对话框
ipcMain.handle('dialog:openFile', async (_event, filters) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: filters || [
      { name: '日志文件', extensions: ['log', 'txt', 'evtx', 'csv'] },
      { name: '所有文件', extensions: ['*'] }
    ]
  });
  if (result.canceled || result.filePaths.length === 0) return null;
  return readFileAsObject(result.filePaths[0]);
});

// 读取文件为可序列化对象
function readFileAsObject(filePath) {
  try {
    const stat = fs.statSync(filePath);
    const buffer = fs.readFileSync(filePath);
    // 转为普通数组来传输（IPC 安全序列化）
    const arr = new Uint8Array(buffer);
    return {
      name: path.basename(filePath),
      size: stat.size,
      data: arr  // Uint8Array, IPC可传
    };
  } catch (err) {
    return { error: err.message };
  }
}

// 发送文件到渲染进程（用于命令行参数和拖拽）
function sendFileToRenderer(filePath) {
  const data = readFileAsObject(filePath);
  if (data && !data.error && mainWindow) {
    mainWindow.webContents.send('file:dropped', data);
  }
}

// 从命令行参数获取文件路径
function getFileFromArgv() {
  const args = process.argv.slice(1).filter(a => !a.startsWith('--') && !a.startsWith('-'));
  return args.find(a => fs.existsSync(a)) || null;
}

// 窗口状态持久化
function getStatePath() {
  return path.join(app.getPath('userData'), 'window-state.json');
}

function restoreWindowBounds() {
  try {
    const data = fs.readFileSync(getStatePath(), 'utf-8');
    const bounds = JSON.parse(data);
    if (bounds.width && bounds.height) mainWindow.setBounds(bounds);
  } catch (_) {}
}

// 系统托盘
function createTray() {
  const iconPath = path.join(__dirname, 'icon.png');
  if (!fs.existsSync(iconPath)) return;
  tray = new Tray(iconPath);
  const contextMenu = Menu.buildFromTemplate([
    { label: '显示窗口', click: () => { mainWindow.show(); mainWindow.focus(); } },
    { type: 'separator' },
    { label: '退出', click: () => { app.isQuitting = true; app.quit(); } }
  ]);
  tray.setToolTip('RavenEye');
  tray.setContextMenu(contextMenu);
  tray.on('click', () => { mainWindow.show(); mainWindow.focus(); });
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  createWindow();



  ipcMain.on('window:minimize', function () { if (mainWindow) mainWindow.minimize(); });

  ipcMain.on('window:maximize', function () {
    if (mainWindow) {
      if (mainWindow.isMaximized()) mainWindow.unmaximize();
      else mainWindow.maximize();
    }
  });

  ipcMain.on('app:quit-yes', function () {
    app.isQuitting = true;
    mainWindow.destroy();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (mainWindow) mainWindow.show();
});



