namespace org.bouncycastle.crypto.tls
{
	public class TlsFatalAlertReceived : TlsException
	{
		protected internal short alertDescription;

		public TlsFatalAlertReceived(short alertDescription) : base(AlertDescription.getText(alertDescription), null)
		{

			this.alertDescription = alertDescription;
		}

		public virtual short getAlertDescription()
		{
			return alertDescription;
		}
	}

}