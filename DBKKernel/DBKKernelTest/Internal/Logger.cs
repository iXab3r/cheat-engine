using System;
using System.IO;
using System.Text;

namespace DBKKernelTest;

internal sealed class Logger
{
    private readonly string _path;
    private readonly object _lock = new object();

    public Logger(string path)
    {
        _path = path;
    }

    public void Info(string fmt, params object[] args) { Write("INFO", fmt, args); }
    public void Warn(string fmt, params object[] args) { Write("WARN", fmt, args); }
    public void Error(string fmt, params object[] args) { Write("ERROR", fmt, args); }
    public void Trace(string fmt, params object[] args) { Write("TRACE", fmt, args); }

    private void Write(string level, string fmt, params object[] args)
    {
        string line;
        try { line = string.Format(fmt, args); }
        catch { line = fmt; }
        string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        string full = string.Format("{0} [{1}] {2}", ts, level, line);
        lock (_lock)
        {
            Console.WriteLine(full);
            try { File.AppendAllText(_path, full + Environment.NewLine, Encoding.UTF8); } catch { /* ignore */ }
        }
    }
}