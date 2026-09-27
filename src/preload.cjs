const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('sentinel', {
  call: (action, payload) => ipcRenderer.invoke('sentinel', action, payload),
  subscribe: callback => {
    const handler = (_, state) => callback(state);
    ipcRenderer.on('state', handler);
    return () => ipcRenderer.removeListener('state', handler);
  }
});
