const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('sentinel', {
  call: (action, payload) => ipcRenderer.invoke('sentinel', action, payload),
  // callback(kind, data): 'state' carries the full state, 'progress' only the live scan/update fields.
  subscribe: callback => {
    const onState = (_, data) => callback('state', data);
    const onProgress = (_, data) => callback('progress', data);
    const onMonitor = (_, data) => callback('monitor', data);
    ipcRenderer.on('state', onState);
    ipcRenderer.on('progress', onProgress);
    ipcRenderer.on('monitor', onMonitor);
    return () => {
      ipcRenderer.removeListener('state', onState);
      ipcRenderer.removeListener('progress', onProgress);
      ipcRenderer.removeListener('monitor', onMonitor);
    };
  }
});
