using System;

namespace org.bouncycastle.crypto.tls
{
	public class TlsFatalAlert : TlsException
	{
		protected internal short alertDescription;

		public TlsFatalAlert(short alertDescription) : this(alertDescription, null)
		{
		}

		public TlsFatalAlert(short alertDescription, Exception alertCause) : base(AlertDescription.getText(alertDescription), alertCause)
		{

			this.alertDescription = alertDescription;
		}

		public virtual short getAlertDescription()
		{
			return alertDescription;
		}
	}

}