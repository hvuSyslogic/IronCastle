namespace org.bouncycastle.mime.smime
{
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;

	public class SMimeParserContext : MimeParserContext
	{
		private readonly string defaultContentTransferEncoding;
		private readonly DigestCalculatorProvider digestCalculatorProvider;

		public SMimeParserContext(string defaultContentTransferEncoding, DigestCalculatorProvider digestCalculatorProvider)
		{
			this.defaultContentTransferEncoding = defaultContentTransferEncoding;
			this.digestCalculatorProvider = digestCalculatorProvider;
		}

		public virtual string getDefaultContentTransferEncoding()
		{
			return defaultContentTransferEncoding;
		}

		public virtual DigestCalculatorProvider getDigestCalculatorProvider()
		{
			return digestCalculatorProvider;
		}
	}

}