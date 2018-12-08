namespace org.bouncycastle.mail.smime.handlers
{


	public class pkcs7_mime : PKCS7ContentHandler
	{
		private static readonly ActivationDataFlavor ADF = new ActivationDataFlavor(typeof(MimeBodyPart), "application/pkcs7-mime", "Encrypted Data");
		private static readonly DataFlavor[] DFS = new DataFlavor[] {ADF};

		public pkcs7_mime() : base(ADF, DFS)
		{
		}
	}

}