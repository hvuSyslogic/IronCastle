using System;

namespace org.bouncycastle.crypto.tls
{

	public abstract class AbstractTlsPeer : TlsPeer
	{
		public abstract TlsCipher getCipher();
		public abstract TlsCompression getCompression();
		public virtual bool requiresExtendedMasterSecret()
		{
			return false;
		}

		public virtual bool shouldUseGMTUnixTime()
		{
			/*
			 * draft-mathewson-no-gmtunixtime-00 2. For the reasons we discuss above, we recommend that
			 * TLS implementors MUST by default set the entire value the ClientHello.Random and
			 * ServerHello.Random fields, including gmt_unix_time, to a cryptographically random
			 * sequence.
			 */
			return false;
		}

		public virtual void notifySecureRenegotiation(bool secureRenegotiation)
		{
			if (!secureRenegotiation)
			{
				/*
				 * RFC 5746 3.4/3.6. In this case, some clients/servers may want to terminate the handshake instead
				 * of continuing; see Section 4.1/4.3 for discussion.
				 */
				throw new TlsFatalAlert(AlertDescription.handshake_failure);
			}
		}

		public virtual void notifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
		{
		}

		public virtual void notifyAlertReceived(short alertLevel, short alertDescription)
		{
		}

		public virtual void notifyHandshakeComplete()
		{
		}
	}

}