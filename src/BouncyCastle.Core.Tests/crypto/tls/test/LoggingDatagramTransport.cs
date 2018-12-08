namespace org.bouncycastle.crypto.tls.test
{

	using Strings = org.bouncycastle.util.Strings;

	public class LoggingDatagramTransport : DatagramTransport
	{

		private const string HEX_CHARS = "0123456789ABCDEF";

		private readonly DatagramTransport transport;
		private readonly PrintStream output;
		private readonly long launchTimestamp;

		public LoggingDatagramTransport(DatagramTransport transport, PrintStream output)
		{
			this.transport = transport;
			this.output = output;
			this.launchTimestamp = System.currentTimeMillis();
		}

		public virtual int getReceiveLimit()
		{
			return transport.getReceiveLimit();
		}

		public virtual int getSendLimit()
		{
			return transport.getSendLimit();
		}

		public virtual int receive(byte[] buf, int off, int len, int waitMillis)
		{
			int length = transport.receive(buf, off, len, waitMillis);
			if (length >= 0)
			{
				dumpDatagram("Received", buf, off, length);
			}
			return length;
		}

		public virtual void send(byte[] buf, int off, int len)
		{
			dumpDatagram("Sending", buf, off, len);
			transport.send(buf, off, len);
		}

		public virtual void close()
		{
		}

		private void dumpDatagram(string verb, byte[] buf, int off, int len)
		{
			long timestamp = System.currentTimeMillis() - launchTimestamp;
			StringBuffer sb = new StringBuffer("(+" + timestamp + "ms) " + verb + " " + len + " byte datagram:");
			for (int pos = 0; pos < len; ++pos)
			{
				if (pos % 16 == 0)
				{
					sb.append(Strings.lineSeparator());
					sb.append("    ");
				}
				else if (pos % 16 == 8)
				{
					sb.append('-');
				}
				else
				{
					sb.append(' ');
				}
				int val = buf[off + pos] & 0xFF;
				sb.append(HEX_CHARS[val >> 4]);
				sb.append(HEX_CHARS[val & 0xF]);
			}
			dump(sb.ToString());
		}

		private void dump(string s)
		{
			lock (this)
			{
				output.println(s);
			}
		}
	}

}