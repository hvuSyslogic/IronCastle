namespace org.bouncycastle.mail.smime.handlers
{


	public class x_pkcs7_mime : PKCS7ContentHandler
	{
		private static readonly ActivationDataFlavor ADF = new ActivationDataFlavor(typeof(MimeBodyPart), "application/x-pkcs7-mime", "Encrypted Data");
		private static readonly DataFlavor[] DFS = new DataFlavor[] {ADF};

		public x_pkcs7_mime() : base(ADF, DFS)
		{
		}
	}

}