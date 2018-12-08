using System.IO;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.tls
{

	public class DTLSTransport : DatagramTransport
	{
		private readonly DTLSRecordLayer recordLayer;

		public DTLSTransport(DTLSRecordLayer recordLayer)
		{
			this.recordLayer = recordLayer;
		}

		public virtual int getReceiveLimit()
		{
			return recordLayer.getReceiveLimit();
		}

		public virtual int getSendLimit()
		{
			return recordLayer.getSendLimit();
		}

		public virtual int receive(byte[] buf, int off, int len, int waitMillis)
		{
			try
			{
				return recordLayer.receive(buf, off, len, waitMillis);
			}
			catch (TlsFatalAlert fatalAlert)
			{
				recordLayer.fail(fatalAlert.getAlertDescription());
				throw fatalAlert;
			}
			catch (IOException e)
			{
				recordLayer.fail(AlertDescription.internal_error);
				throw e;
			}
			catch (RuntimeException e)
			{
				recordLayer.fail(AlertDescription.internal_error);
				throw new TlsFatalAlert(AlertDescription.internal_error, e);
			}
		}

		public virtual void send(byte[] buf, int off, int len)
		{
			try
			{
				recordLayer.send(buf, off, len);
			}
			catch (TlsFatalAlert fatalAlert)
			{
				recordLayer.fail(fatalAlert.getAlertDescription());
				throw fatalAlert;
			}
			catch (IOException e)
			{
				recordLayer.fail(AlertDescription.internal_error);
				throw e;
			}
			catch (RuntimeException e)
			{
				recordLayer.fail(AlertDescription.internal_error);
				throw new TlsFatalAlert(AlertDescription.internal_error, e);
			}
		}

		public virtual void close()
		{
			recordLayer.close();
		}
	}

}