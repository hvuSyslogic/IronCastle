namespace org.bouncycastle.mail.smime.handlers
{


	public class pkcs7_signature : PKCS7ContentHandler
	{
		private static readonly ActivationDataFlavor ADF = new ActivationDataFlavor(typeof(MimeBodyPart), "application/pkcs7-signature", "Signature");
		private static readonly DataFlavor[] DFS = new DataFlavor[] {ADF};

		public pkcs7_signature() : base(ADF, DFS)
		{
		}
	}

}