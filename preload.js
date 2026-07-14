const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  openFile: (filters) => ipcRenderer.invoke('dialog:openFile', filters),

  onFileDrop: (callback) => {
    ipcRenderer.on('file:dropped', (_event, fileData) => callback(fileData));
  },

  onConfirmQuit: (callback) => {
    ipcRenderer.on('app:confirm-quit', function () { callback(); });
  },

  doQuit: () => {
    ipcRenderer.send('app:quit-yes');
  },

  minimize: () => ipcRenderer.send('window:minimize'),
  maximize: () => ipcRenderer.send('window:maximize'),
});

