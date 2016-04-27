namespace System.Net.FtpClient
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;

    public static class FtpTrace
    {
        private static bool m_flushOnWrite = false;
        private static List<TraceListener> m_listeners = new List<TraceListener>();

        public static void AddListener(TraceListener listener)
        {
            lock (m_listeners)
            {
                m_listeners.Add(listener);
            }
        }

        public static void RemoveListener(TraceListener listener)
        {
            lock (m_listeners)
            {
                m_listeners.Remove(listener);
            }
        }

        public static void Write(string message)
        {
            TraceListener[] listenerArray;
            lock (m_listeners)
            {
                listenerArray = m_listeners.ToArray();
            }
            foreach (TraceListener listener in listenerArray)
            {
                listener.Write(message);
                if (m_flushOnWrite)
                {
                    listener.Flush();
                }
            }
        }

        public static void Write(string message, params object[] args)
        {
            Write(string.Format(message, args));
        }

        public static void WriteLine(string message)
        {
            Write(string.Format("{0}{1}", message, Environment.NewLine));
        }

        public static void WriteLine(string message, params object[] args)
        {
            Write(string.Format("{0}{1}", string.Format(message, args), Environment.NewLine));
        }

        public static bool FlushOnWrite
        {
            get
            {
                return m_flushOnWrite;
            }
            set
            {
                m_flushOnWrite = value;
            }
        }
    }
}

